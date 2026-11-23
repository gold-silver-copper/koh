//! Headless persistent background jobs backed by raw append-only log files
//! (no PTY, no 80-column wrapping, no 4 MiB screen truncation).

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Seek as _, SeekFrom};
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::watch;

use crate::proto::{JobInfo, WaitResult};
use crate::{Exit, KohError, Result, atomic_write, is_safe_name};

struct JobRecord {
    name: String,
    pid: u32,
    command: String,
    dir: PathBuf,
    started: Instant,
    state_tx: watch::Sender<(String, Option<i32>)>,
}

/// Manages detached headless jobs on the server.
pub struct JobManager {
    root: PathBuf,
    next_id: u32,
    jobs: BTreeMap<String, Arc<JobRecord>>,
}

pub type JobStateRx = watch::Receiver<(String, Option<i32>)>;

pub struct JobHandle {
    pub log_path: PathBuf,
    pub state_rx: JobStateRx,
    pub started: Instant,
}

impl JobManager {
    pub fn new(root: PathBuf) -> Result<Self> {
        fs::create_dir_all(&root)
            .map_err(|e| KohError::failed(format!("mkdir {}: {e}", root.display())))?;
        Ok(Self {
            root,
            next_id: 1,
            jobs: BTreeMap::new(),
        })
    }

    pub fn start(
        mgr: &Arc<Mutex<Self>>,
        name: Option<String>,
        argv: &[String],
        cwd: &Path,
        shell: bool,
    ) -> Result<JobInfo> {
        let mut guard = mgr
            .lock()
            .map_err(|_| KohError::internal("job lock poisoned"))?;
        let job_name = match name {
            Some(n) => {
                if !is_safe_name(&n) {
                    return Err(KohError::usage(format!("invalid job name {n:?}")));
                }
                if let Some(existing) = guard.jobs.get(&n)
                    && existing.state_tx.borrow().0 == "running"
                {
                    return Err(KohError::failed(format!("job {n:?} is already running")));
                }
                n
            }
            None => loop {
                let cand = format!("j{}", guard.next_id);
                guard.next_id = guard.next_id.wrapping_add(1);
                if !guard.jobs.contains_key(&cand) {
                    break cand;
                }
            },
        };
        let dir = guard.root.join(&job_name);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).map_err(|e| KohError::failed(format!("mkdir job dir: {e}")))?;

        let log_path = dir.join("log");
        let log_out = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&log_path)
            .map_err(|e| KohError::failed(format!("create job log: {e}")))?;
        let log_err = log_out
            .try_clone()
            .map_err(|e| KohError::failed(format!("clone log fd: {e}")))?;

        let mut cmd = build_command(argv, cwd, shell)?;
        fuxix::new_session(&mut cmd, false);
        cmd.stdin(Stdio::null())
            .stdout(Stdio::from(log_out))
            .stderr(Stdio::from(log_err));

        let mut child = cmd.spawn().map_err(|e| {
            let code = if e.kind() == std::io::ErrorKind::NotFound {
                Exit::NOT_FOUND
            } else {
                Exit::CANNOT_START
            };
            KohError::new(code, "cannot_start", format!("spawn job: {e}"))
        })?;
        let pid = child.id();
        let command_str = argv.join(" ");
        let _ = atomic_write(&dir.join("state"), b"running\n");
        let _ = atomic_write(
            &dir.join("meta"),
            format!("pid {pid}\ncommand {command_str}\n").as_bytes(),
        );

        let (state_tx, _) = watch::channel(("running".to_string(), None));
        let rec = Arc::new(JobRecord {
            name: job_name.clone(),
            pid,
            command: command_str.clone(),
            dir: dir.clone(),
            started: Instant::now(),
            state_tx,
        });
        guard.jobs.insert(job_name.clone(), rec.clone());
        drop(guard);

        let dir_wait = dir.clone();
        std::thread::spawn(move || {
            let (state, code) = match child.wait() {
                Ok(status) => {
                    if let Some(c) = status.code() {
                        (format!("exited {c}"), Some(c))
                    } else if let Some(sig) = status.signal() {
                        (format!("killed {sig}"), Some(128 + sig))
                    } else {
                        ("exited 1".to_string(), Some(1))
                    }
                }
                Err(e) => (format!("lost {e}"), Some(1)),
            };
            let _ = atomic_write(&dir_wait.join("state"), format!("{state}\n").as_bytes());
            let _ = rec.state_tx.send_replace((state, code));
        });

        Ok(JobInfo {
            name: job_name,
            pid,
            state: "running".into(),
            exit: None,
            age_secs: 0,
            command: command_str,
        })
    }

    pub fn list(&self, filter: Option<&str>) -> Result<Vec<JobInfo>> {
        if let Some(name) = filter {
            let rec = self.jobs.get(name).ok_or_else(|| {
                KohError::new(
                    Exit::NOT_FOUND,
                    "not_found",
                    format!("no job named {name:?}"),
                )
            })?;
            return Ok(vec![record_info(rec)]);
        }
        Ok(self.jobs.values().map(|r| record_info(r)).collect())
    }

    pub fn get(&self, name: &str) -> Result<JobHandle> {
        let rec = self.jobs.get(name).ok_or_else(|| {
            KohError::new(
                Exit::NOT_FOUND,
                "not_found",
                format!("no job named {name:?}"),
            )
        })?;
        Ok(JobHandle {
            log_path: rec.dir.join("log"),
            state_rx: rec.state_tx.subscribe(),
            started: rec.started,
        })
    }

    pub fn kill(&self, name: &str, sig: i32) -> Result<JobInfo> {
        let rec = self.jobs.get(name).ok_or_else(|| {
            KohError::new(
                Exit::NOT_FOUND,
                "not_found",
                format!("no job named {name:?}"),
            )
        })?;
        let pid_i32 = i32::try_from(rec.pid).map_err(|_| KohError::failed("invalid pid"))?;
        if let Some(pid) = rustix::process::Pid::from_raw(pid_i32) {
            let signal = rustix::process::Signal::from_named_raw(sig)
                .unwrap_or(rustix::process::Signal::TERM);
            let _ = rustix::process::kill_process_group(pid, signal);
        }
        Ok(record_info(rec))
    }
}

fn record_info(rec: &JobRecord) -> JobInfo {
    let (state, exit) = rec.state_tx.borrow().clone();
    JobInfo {
        name: rec.name.clone(),
        pid: rec.pid,
        state,
        exit,
        age_secs: rec.started.elapsed().as_secs(),
        command: rec.command.clone(),
    }
}

/// Builds a `std::process::Command` from argv (either raw exec or `sh -c` when `shell = true`).
pub fn build_command(argv: &[String], cwd: &Path, shell: bool) -> Result<Command> {
    if !cwd.is_dir() {
        return Err(KohError::new(
            Exit::CANNOT_START,
            "cannot_start",
            format!("no such directory: {}", cwd.display()),
        ));
    }
    let mut cmd = if shell {
        let line = argv
            .first()
            .ok_or_else(|| KohError::usage("missing shell command"))?;
        let mut c = Command::new("/bin/sh");
        c.arg("-c").arg(line);
        c
    } else {
        let Some((prog, args)) = argv.split_first() else {
            return Err(KohError::usage("missing command"));
        };
        let mut c = Command::new(prog);
        c.args(args);
        c
    };
    cmd.current_dir(cwd);
    Ok(cmd)
}

/// Reads the last `tail_lines` lines (or all bytes if `tail_lines == None`) of a job log file.
pub fn read_log_tail(path: &Path, tail_lines: Option<usize>) -> Result<Vec<u8>> {
    let data = fs::read(path).map_err(|e| KohError::failed(format!("read log: {e}")))?;
    let Some(n) = tail_lines else {
        return Ok(data);
    };
    if n == 0 {
        return Ok(Vec::new());
    }
    let mut lines = 0usize;
    let mut start = data.len();
    for (i, &b) in data.iter().enumerate().rev() {
        if b == b'\n' && i + 1 < data.len() {
            lines += 1;
            if lines >= n {
                start = i + 1;
                break;
            }
        }
        start = i;
    }
    Ok(data.get(start..).unwrap_or_default().to_vec())
}

/// Waits for a job to finish (or for `text` to appear in its raw log), up to `timeout_secs`.
pub async fn wait_job(
    log_path: PathBuf,
    mut state_rx: watch::Receiver<(String, Option<i32>)>,
    text: Option<String>,
    tail: usize,
    timeout_secs: Option<u64>,
) -> Result<WaitResult> {
    let deadline = timeout_secs.map(|s| Instant::now() + Duration::from_secs(s));
    let mut scan_offset = 0u64;

    loop {
        if let Some(needle) = text.as_deref()
            && let Ok(mut f) = File::open(&log_path)
            && f.seek(SeekFrom::Start(scan_offset)).is_ok()
        {
            let mut chunk = Vec::new();
            if f.read_to_end(&mut chunk).is_ok() {
                if String::from_utf8_lossy(&chunk).contains(needle) {
                    let tail_bytes = read_log_tail(&log_path, Some(tail)).unwrap_or_default();
                    return Ok(WaitResult {
                        timed_out: false,
                        exit: 0,
                        tail: String::from_utf8_lossy(&tail_bytes).into_owned(),
                        detail: "matched".into(),
                    });
                }
                // Keep small overlap so matches straddling reads are never missed.
                let overlap = needle.len().saturating_sub(1) as u64;
                let end = scan_offset.saturating_add(chunk.len() as u64);
                scan_offset = end.saturating_sub(overlap);
            }
        }

        let (state, exit) = state_rx.borrow().clone();
        if state != "running" {
            let tail_bytes = read_log_tail(&log_path, Some(tail)).unwrap_or_default();
            let tail_str = String::from_utf8_lossy(&tail_bytes).into_owned();
            if text.is_some() {
                return Ok(WaitResult {
                    timed_out: false,
                    exit: 1,
                    tail: tail_str,
                    detail: format!("job ended ({state}) before text matched"),
                });
            }
            return Ok(WaitResult {
                timed_out: false,
                exit: exit.unwrap_or(1),
                tail: tail_str,
                detail: state,
            });
        }

        if let Some(dl) = deadline
            && Instant::now() >= dl
        {
            let tail_bytes = read_log_tail(&log_path, Some(tail)).unwrap_or_default();
            return Ok(WaitResult {
                timed_out: true,
                exit: i32::from(Exit::TIMEOUT.0),
                tail: String::from_utf8_lossy(&tail_bytes).into_owned(),
                detail: "timed out".into(),
            });
        }

        let sleep = if text.is_some() {
            Duration::from_millis(25)
        } else {
            Duration::from_millis(200)
        };
        let wait_for = deadline.map_or(sleep, |dl| {
            dl.saturating_duration_since(Instant::now()).min(sleep)
        });
        tokio::select! {
            _ = state_rx.changed() => {}
            () = tokio::time::sleep(wait_for) => {}
        }
    }
}
