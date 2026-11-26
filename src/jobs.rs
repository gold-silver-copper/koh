//! Jobs backed by terminal-less fux panes (`fux start --out`) in `STATE/fux/koh-jobs/NAME`.
//! `koh serve` keeps no in-memory job table: the pane folders are the jobs, so jobs survive
//! restarts of `koh serve` and logs stream in fixed-size chunks without reading whole files.

use std::fs::{self, DirBuilder, File};
use std::io::{ErrorKind, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, FileExt as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use fux::run_of;
use iroh::endpoint::SendStream;
use tokio::time::Instant as Timer;

use crate::pane;
use crate::proto::{
    JobInfo, LogMsg, MAX_CHUNK, MAX_CTRL, MAX_FRAME, Reply, WaitResult, send_msg, session_name,
};
use crate::session::{ended, lives, not_found, panes_in, pooled, start, state_now};
use crate::{Exit, KohError, Result, after};

const PIECE: usize = 64 << 10;
const WAIT_TAIL_CAP: usize = MAX_FRAME - 4096;
const REPLACED: &str = "that job was started anew";

pub struct Jobs {
    dir: PathBuf,
    exe: PathBuf,
    starting: tokio::sync::Mutex<()>,
}

enum PollEnd {
    ClientGone,
    TimedOut,
    State(String, Option<i32>),
}

fn read_err(e: std::io::Error) -> KohError {
    KohError::failed(format!("read log: {e}"))
}

fn info(dir: &Path) -> JobInfo {
    let state = state_now(dir, lives);
    let status = pane::read(dir, "status").unwrap_or_default();
    let status = String::from_utf8_lossy(&status);
    let field = |k: &str| status.lines().find_map(|l| l.strip_prefix(k)).unwrap_or("");
    let age_secs = fs::metadata(dir.join("status"))
        .and_then(|m| m.modified())
        .ok()
        .and_then(|at| at.elapsed().ok())
        .map_or(0, |d| d.as_secs());
    JobInfo {
        name: dir.file_name().unwrap_or_default().to_string_lossy().into(),
        pid: field("pid ").parse().unwrap_or(0),
        exit: pane::code(&state).or((state == "ended").then_some(1)),
        state,
        age_secs,
        command: field("command ").into(),
    }
}

fn read_chunk(file: &File, at: u64, lim: Option<u64>) -> Result<Option<Vec<u8>>> {
    let want = lim
        .map_or(PIECE as u64, |e| e.saturating_sub(at))
        .min(PIECE as u64) as usize;
    if want == 0 {
        return Ok(None);
    }
    let mut buf = vec![0u8; want];
    let n = loop {
        match file.read_at(&mut buf, at) {
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            res => break res.map_err(read_err)?,
        }
    };
    buf.truncate(n);
    Ok((n > 0).then_some(buf))
}

/// Finds `(start_offset, file_len)` for the last `lines` lines by scanning backwards in `PIECE`
/// blocks, bounded to at most `max_bytes` from the end.
fn tail_range(file: &File, lines: usize, max_bytes: u64) -> std::io::Result<(u64, u64)> {
    let len = file.metadata()?.len();
    if lines == 0 {
        return Ok((len, len));
    }
    let (floor, mut found, mut end) = (len.saturating_sub(max_bytes), 0usize, len);
    while end > floor {
        let from = end.saturating_sub(PIECE as u64).max(floor);
        let mut piece = vec![0u8; (end - from) as usize];
        file.read_exact_at(&mut piece, from)?;
        for (i, &byte) in piece.iter().enumerate().rev() {
            let at = from + i as u64;
            if byte == b'\n' && at + 1 < len {
                found += 1;
                if found == lines {
                    return Ok((at + 1, len));
                }
            }
        }
        end = from;
    }
    Ok((floor, len))
}

impl Jobs {
    pub fn new(state: &Path, exe: &Path) -> Result<Self> {
        let dir = state.join("fux").join("koh-jobs");
        let dir = DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(&dir)
            .and_then(|()| fs::canonicalize(&dir))
            .map_err(|e| KohError::failed(format!("koh-jobs: {e}")))?;
        Ok(Self {
            dir,
            exe: exe.to_path_buf(),
            starting: tokio::sync::Mutex::new(()),
        })
    }

    fn named(&self, name: &str) -> Result<(PathBuf, u128)> {
        let dir = session_name(name).then(|| self.dir.join(name));
        dir.filter(|d| d.join("status").is_file())
            .and_then(|d| Some((d.clone(), run_of(&d)?)))
            .ok_or_else(|| not_found(format!("no job named {name:?}")))
    }

    /// Resolves `name` and opens `out` under `starting`, binding the fd to `run`, and optionally
    /// computes `(offset, len)` for `logs`.
    async fn open_run(
        &self,
        name: &str,
        tail: Option<Option<usize>>,
    ) -> Result<(PathBuf, u128, SystemTime, Arc<File>, (u64, u64))> {
        let _one = self.starting.lock().await;
        let (dir, run) = self.named(name)?;
        let d = dir.clone();
        let (at, file, range) = pooled(move || -> Result<_> {
            let at = fs::metadata(d.join("status"))
                .and_then(|m| m.modified())
                .unwrap_or(SystemTime::UNIX_EPOCH);
            let file = fuxix::open_regular(d.join("out")).map_err(read_err)?;
            let range = match tail {
                None => (0, 0),
                Some(None) => (0, file.metadata().map_err(read_err)?.len()),
                Some(Some(n)) => tail_range(&file, n, u64::MAX).map_err(read_err)?,
            };
            Ok((at, file, range))
        })
        .await??;
        Ok((dir, run, at, Arc::new(file), range))
    }

    pub async fn run(
        &self,
        name: Option<String>,
        argv: Vec<String>,
        cwd: &Path,
    ) -> Result<JobInfo> {
        if !name.as_deref().is_none_or(session_name) {
            return Err(KohError::usage(format!("invalid job name {name:?}")));
        }
        crate::server::check_cmd(&argv, cwd)?;
        let name = name.unwrap_or_default();
        let _one = self.starting.lock().await;
        if !name.is_empty() {
            let dir = self.dir.join(&name);
            if lives(&dir) {
                return Err(KohError::failed(format!("job {name:?} is already running")));
            }
            let _ = fs::remove_dir_all(&dir);
        }
        let dir = start(&self.exe, &self.dir, &name, true, &argv, &[], cwd).await?;
        pooled(move || info(&dir)).await
    }

    pub async fn list(&self, name: Option<String>) -> Result<Vec<JobInfo>> {
        if let Some(name) = name {
            let (dir, _) = self.named(&name)?;
            return pooled(move || vec![info(&dir)]).await;
        }
        let root = self.dir.clone();
        pooled(move || {
            let mut jobs: Vec<_> = panes_in(&root)
                .into_iter()
                .filter_map(|(dir, pane)| Some((pane?.1, dir)))
                .collect();
            jobs.sort();
            jobs.into_iter().map(|(_, dir)| info(&dir)).collect()
        })
        .await
    }

    /// Writes `kill N` non-blockingly to `ctl` under `starting` (never signals a PID from a file).
    pub async fn kill(&self, name: &str, signal: i32) -> Result<JobInfo> {
        if !(1..32).contains(&signal) {
            return Err(KohError::usage(format!("invalid signal {signal}")));
        }
        let _one = self.starting.lock().await;
        let (dir, _) = self.named(name)?;
        pooled(move || {
            let job = info(&dir);
            let res = fuxix::open_fifo(dir.join("ctl"))
                .and_then(|mut c| c.write_all(format!("kill {signal}\n").as_bytes()));
            match res {
                Ok(()) => Ok(job),
                Err(e)
                    if fuxix::no_reader(&e)
                        || matches!(e.kind(), ErrorKind::NotFound | ErrorKind::BrokenPipe) =>
                {
                    Ok(info(&dir))
                }
                Err(e) => Err(KohError::failed(format!("kill -{signal}: {e}"))),
            }
        })
        .await?
    }

    pub async fn logs(
        &self,
        name: &str,
        lines: Option<usize>,
        all: bool,
        follow: bool,
        send: &mut SendStream,
    ) -> Result<()> {
        let want = Some(if all { None } else { lines.or(Some(200)) });
        let (dir, run, at, file, (offset, snap)) = self.open_run(name, want).await?;
        send_msg(send, &Reply::Ok, MAX_CTRL).await?;
        let out = Some((file, offset, (!follow).then_some(snap)));
        let PollEnd::State(state, exit) = self.until_ended(&dir, run, None, send, out).await?
        else {
            return Ok(());
        };
        let age_secs = at.elapsed().map_or(0, |d| d.as_secs());
        send_msg(
            send,
            &LogMsg::Done {
                state,
                exit,
                age_secs,
            },
            MAX_CTRL,
        )
        .await
    }

    pub async fn wait(
        &self,
        name: &str,
        lines: usize,
        timeout_secs: Option<u64>,
        send: &mut SendStream,
    ) -> Result<()> {
        let (dir, run, _, file, _) = self.open_run(name, None).await?;
        send_msg(send, &Reply::Ok, MAX_CTRL).await?;
        let deadline = timeout_secs.map(|s| after(Timer::now(), Duration::from_secs(s)));
        let (timed_out, exit, detail) =
            match self.until_ended(&dir, run, deadline, send, None).await? {
                PollEnd::ClientGone => return Ok(()),
                PollEnd::State(st, code) => (false, code.unwrap_or(1), st),
                PollEnd::TimedOut => (true, i32::from(Exit::TIMEOUT.0), "timed out".into()),
            };
        let tail = pooled(move || -> Result<String> {
            let (from, len) = tail_range(&file, lines, WAIT_TAIL_CAP as u64).map_err(read_err)?;
            let mut raw = vec![0u8; (len - from) as usize];
            file.read_exact_at(&mut raw, from).map_err(read_err)?;
            let mut tail = String::from_utf8_lossy(&raw).into_owned();
            tail.drain(..tail.ceil_char_boundary(tail.len().saturating_sub(WAIT_TAIL_CAP)));
            Ok(tail)
        })
        .await??;
        let waited = WaitResult {
            timed_out,
            exit,
            tail,
            detail,
        };
        send_msg(send, &waited, MAX_FRAME).await
    }

    /// Shared poll loop for `logs`, `logs -f`, and `wait`: `wait` polls every 200 ms; `logs -f`
    /// polls at 25 ms while bytes come and backs off to 200 ms when quiet.
    async fn until_ended(
        &self,
        dir: &Path,
        run: u128,
        deadline: Option<Timer>,
        send: &mut SendStream,
        mut out: Option<(Arc<File>, u64, Option<u64>)>,
    ) -> Result<PollEnd> {
        let mut poll = Duration::from_millis(if out.is_some() { 25 } else { 200 });
        loop {
            let d = dir.to_path_buf();
            let reading = out.as_ref().map(|(f, at, lim)| (Arc::clone(f), *at, *lim));
            let (was, chunk) = pooled(move || -> Result<(_, Option<Vec<u8>>)> {
                if let Some((f, at, lim)) = reading {
                    if let Some(chunk) = read_chunk(&f, at, lim)? {
                        return Ok((None, Some(chunk)));
                    }
                    // Check `ended` before a final read of `out`: follow stops at leader exit
                    // (leftover children that ignore SIGHUP and write later stay in `out`).
                    let was = ended(&d, run);
                    let tail = if lim.is_none() {
                        read_chunk(&f, at, None)?
                    } else {
                        None
                    };
                    Ok((was, tail))
                } else {
                    Ok((ended(&d, run), None))
                }
            })
            .await??;
            if let Some(chunk) = chunk {
                if let Some((_, at, _)) = out.as_mut() {
                    *at += chunk.len() as u64;
                }
                poll = Duration::from_millis(25);
                send_msg(send, &LogMsg::Data(chunk), MAX_CHUNK).await?;
                continue;
            }
            if matches!(out, Some((_, _, Some(_)))) || was.is_some() {
                let (st, code) = match was {
                    None => ("running".into(), None),
                    Some(Err(())) => (REPLACED.into(), Some(1)),
                    Some(Ok(st)) => {
                        let c = pane::code(&st).or((st == "ended").then_some(1));
                        (st, c)
                    }
                };
                return Ok(PollEnd::State(st, code));
            }
            if deadline.is_some_and(|dl| Timer::now() >= dl) {
                return Ok(PollEnd::TimedOut);
            }
            let wait_for = deadline.map_or(poll, |dl| {
                dl.saturating_duration_since(Timer::now()).min(poll)
            });
            tokio::select! {
                _ = send.stopped() => return Ok(PollEnd::ClientGone),
                () = tokio::time::sleep(wait_for) => {}
            }
            if out.is_some() {
                poll = (poll * 2).min(Duration::from_millis(200));
            }
        }
    }
}
