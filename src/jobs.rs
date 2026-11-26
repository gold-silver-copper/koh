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
use crate::session::{ended, lives, not_found, panes_in, pooled, start, state_of};
use crate::{Exit, KohError, Result, after};

/// Chunk size for streaming logs and seeking backwards for tails.
const PIECE: usize = 64 << 10;

/// Maximum tail bytes packed into a single `WaitResult` (`MAX_FRAME` minus framing headroom).
const WAIT_TAIL_CAP: u64 = (MAX_FRAME - 4096) as u64;

pub struct Jobs {
    dir: PathBuf,
    exe: PathBuf,
    starting: tokio::sync::Mutex<()>,
}

/// Reads a job's summary from its folder (`lives` checked before `state` so a freshly-unlocked
/// folder always observes the holder's final `state`).
fn info(dir: &Path) -> JobInfo {
    let status =
        String::from_utf8_lossy(&pane::read(dir, "status").unwrap_or_default()).into_owned();
    let field = |key: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(key))
            .unwrap_or_default()
            .to_string()
    };
    let state = state_of(pane::line(dir, "state"), lives(dir));
    let age_secs = fs::metadata(dir.join("status"))
        .and_then(|m| m.modified())
        .ok()
        .and_then(|at| SystemTime::now().duration_since(at).ok())
        .map_or(0, |d| d.as_secs());
    JobInfo {
        name: dir.file_name().unwrap_or_default().to_string_lossy().into(),
        pid: field("pid ").parse().unwrap_or(0),
        exit: pane::code(&state).or((state == "ended").then_some(1)),
        state,
        age_secs,
        command: field("command "),
    }
}

fn read_piece(file: &File, from: u64, len: usize) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    let mut got = 0;
    while let Some(rest) = buf.get_mut(got..)
        && !rest.is_empty()
    {
        match file.read_at(rest, from + got as u64) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    buf.truncate(got);
    Ok(buf)
}

/// Finds `(start_offset, file_len)` for the last `lines` lines by scanning backwards in `PIECE`
/// blocks, bounded to at most `max_bytes` from the end.
fn tail_range(file: &File, lines: usize, max_bytes: u64) -> std::io::Result<(u64, u64)> {
    let len = file.metadata().map_or(0, |m| m.len());
    if lines == 0 {
        return Ok((len, len));
    }
    let (floor, mut found, mut end) = (len.saturating_sub(max_bytes), 0usize, len);
    while end > floor {
        let from = end.saturating_sub(PIECE as u64).max(floor);
        let piece = read_piece(file, from, (end - from) as usize)?;
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

    /// `koh run`: starts a `--out` pane under `name` (removing an ended folder first) or fux's
    /// first free number.
    pub async fn run(
        &self,
        name: Option<String>,
        argv: Vec<String>,
        cwd: &Path,
    ) -> Result<JobInfo> {
        if !name.as_deref().is_none_or(session_name) {
            return Err(KohError::usage(format!("invalid job name {name:?}")));
        }
        if !cwd.is_dir() {
            return Err(KohError::new(
                Exit::CANNOT_START,
                "cannot_start",
                format!("no such directory: {}", cwd.display()),
            ));
        }
        if argv.is_empty() {
            return Err(KohError::usage("missing command"));
        }
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

    /// `koh jobs`: lists all jobs oldest-first, or the named job.
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

    /// `koh kill`: writes `kill N` non-blockingly to `ctl` so the holder signals its program's
    /// process group. Never signals a PID read from a file.
    pub async fn kill(&self, name: &str, signal: i32) -> Result<JobInfo> {
        if !(1..32).contains(&signal) {
            return Err(KohError::usage(format!("invalid signal {signal}")));
        }
        let (dir, run) = self.named(name)?;
        pooled(move || {
            if ended(&dir, run).is_none() {
                match fuxix::open_fifo(dir.join("ctl")) {
                    Ok(mut ctl) => {
                        if let Err(e) = ctl.write_all(format!("kill {signal}\n").as_bytes())
                            && e.kind() != ErrorKind::BrokenPipe
                        {
                            return Err(KohError::failed(format!("kill -{signal}: {e}")));
                        }
                    }
                    // ENOENT or ENXIO (6 on Linux and macOS): holder is already gone.
                    Err(e) if e.kind() == ErrorKind::NotFound || e.raw_os_error() == Some(6) => {}
                    Err(e) => return Err(KohError::failed(format!("kill -{signal}: {e}"))),
                }
            }
            Ok(info(&dir))
        })
        .await?
    }

    /// `koh logs`: streams `out` from the tail offset (or 0 for `--all`) in 64 KiB chunks,
    /// optionally following until the job ends.
    pub async fn logs(
        &self,
        name: &str,
        lines: Option<usize>,
        all: bool,
        follow: bool,
        send: &mut SendStream,
    ) -> Result<()> {
        let (dir, run) = self.named(name)?;
        let path = dir.join("out");
        send_msg(send, &Reply::Ok, MAX_CTRL).await?;
        let (file, offset, snap) = pooled(move || -> Result<(Arc<File>, u64, u64)> {
            let file = fuxix::open_regular(&path)
                .map_err(|e| KohError::failed(format!("read log: {e}")))?;
            let (from, snap) = match if all { None } else { lines.or(Some(200)) } {
                None => (0, file.metadata().map_or(0, |m| m.len())),
                Some(n) => tail_range(&file, n, u64::MAX)
                    .map_err(|e| KohError::failed(format!("read log: {e}")))?,
            };
            Ok((Arc::new(file), from, snap))
        })
        .await??;
        let out = Some((file, offset, (!follow).then_some(snap)));
        if self
            .until_ended(&dir, run, None, send, out)
            .await?
            .is_none()
        {
            return Ok(());
        }
        let job = pooled(move || info(&dir)).await?;
        send_msg(
            send,
            &LogMsg::Done {
                state: job.state,
                exit: job.exit,
                age_secs: job.age_secs,
            },
            MAX_CTRL,
        )
        .await
    }

    /// `koh wait`: waits until the job ends or `timeout_secs` elapses, then returns the tail.
    pub async fn wait(
        &self,
        name: &str,
        lines: usize,
        timeout_secs: Option<u64>,
        send: &mut SendStream,
    ) -> Result<()> {
        let (dir, run) = self.named(name)?;
        let out = dir.join("out");
        send_msg(send, &Reply::Ok, MAX_CTRL).await?;
        let deadline = timeout_secs.map(|s| after(Timer::now(), Duration::from_secs(s)));
        let Some(outcome) = self.until_ended(&dir, run, deadline, send, None).await? else {
            return Ok(());
        };
        let (timed_out, exit, detail) = match outcome {
            Some(code) => {
                let d = dir.clone();
                (false, code, pooled(move || info(&d).state).await?)
            }
            None => (true, i32::from(Exit::TIMEOUT.0), "timed out".into()),
        };
        let last = pooled(move || {
            fuxix::open_regular(&out)
                .and_then(|f| {
                    let (from, len) = tail_range(&f, lines, WAIT_TAIL_CAP)?;
                    read_piece(&f, from, (len - from) as usize)
                })
                .unwrap_or_default()
        })
        .await?;
        let waited = WaitResult {
            timed_out,
            exit,
            tail: String::from_utf8_lossy(&last).into_owned(),
            detail,
        };
        send_msg(send, &waited, MAX_FRAME).await
    }

    /// Shared poll loop for `logs`, `logs -f`, and `wait`: streams chunks from `out` (if any)
    /// until snapshot EOF, job end, `deadline`, or client disconnect (`send.stopped()`).
    async fn until_ended(
        &self,
        dir: &Path,
        run: u128,
        deadline: Option<Timer>,
        send: &mut SendStream,
        mut out: Option<(Arc<File>, u64, Option<u64>)>,
    ) -> Result<Option<Option<i32>>> {
        loop {
            let d = dir.to_path_buf();
            let reading = out.as_ref().map(|(f, at, lim)| (Arc::clone(f), *at, *lim));
            let (was, chunk) = pooled(move || {
                let read = |f: &File, at: u64, lim: Option<u64>| {
                    let want = lim
                        .map_or(PIECE as u64, |e| e.saturating_sub(at))
                        .min(PIECE as u64);
                    (want > 0)
                        .then(|| read_piece(f, at, want as usize).unwrap_or_default())
                        .filter(|bytes| !bytes.is_empty())
                };
                if let Some((f, at, lim)) = reading {
                    if let Some(chunk) = read(&f, at, lim) {
                        return (None, Some(chunk));
                    }
                    if lim.is_some() {
                        return (None, None);
                    }
                    // Check `ended` BEFORE re-reading `out`: the holder drains `out` before
                    // writing final `state`, so once `was` is `Some`, no more bytes can arrive.
                    let was = ended(&d, run);
                    (was, read(&f, at, None))
                } else {
                    (ended(&d, run), None)
                }
            })
            .await?;
            if let Some(chunk) = chunk {
                if let Some((_, at, _)) = out.as_mut() {
                    *at += chunk.len() as u64;
                }
                send_msg(send, &LogMsg::Data(chunk), MAX_CHUNK).await?;
                continue;
            }
            if matches!(out, Some((_, _, Some(_)))) || was.is_some() {
                return Ok(Some(was));
            }
            if deadline.is_some_and(|dl| Timer::now() >= dl) {
                return Ok(Some(None));
            }
            let sleep = Duration::from_millis(25);
            let wait_for = deadline.map_or(sleep, |dl| {
                dl.saturating_duration_since(Timer::now()).min(sleep)
            });
            tokio::select! {
                _ = send.stopped() => return Ok(None),
                () = tokio::time::sleep(wait_for) => {}
            }
        }
    }
}
