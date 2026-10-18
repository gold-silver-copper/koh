//! Jobs (`koh run`): commands with no terminal that outlive the connection that started them,
//! their output and status kept.
//!
//! A job is a peer's, by name: given, or the next number. Its stdout and stderr go together into
//! a log of at most `job_log_bytes`, the oldest dropped past it (and counted); its stdin is
//! `/dev/null`. It runs until it exits, is signalled (`koh kill`), or the server stops, which
//! hangs it up. A job that ended is kept, with its log and status, until its name is used again,
//! room is needed for a new one, or the session TTL has passed since it ended.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iroh::EndpointId;
use tokio::io::AsyncReadExt as _;
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;

use super::cli::Host;
use super::place::Place;
use crate::request::{
    JobInfo, JobList, JobName, JobState, LogMsg, Problem, ProblemKind, Run, Signal, Started,
    MAX_LOG_CHUNK,
};

/// Most jobs kept, all peers', running and ended together.
pub const MAX_JOBS: usize = 64;

/// How often a job's exit is looked for while it writes.
const EXIT_POLL: Duration = Duration::from_millis(50);

/// How long a job's output must be quiet, after it exited, to count as drained.
const DRAINED: Duration = Duration::from_millis(100);

/// The status of a job hung up by the server's shutdown, as one hung up by its terminal.
const HUNG_UP: u32 = 128 + 1;

/// A job's log: the newest bytes it wrote, at most twice its budget held at once.
#[derive(Debug, Default)]
struct Log {
    kept: Vec<u8>,
    /// Bytes written in all, the dropped ones included.
    total: u64,
    budget: usize,
}

impl Log {
    fn append(&mut self, bytes: &[u8]) {
        self.kept.extend_from_slice(bytes);
        self.total = self
            .total
            .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        // Dropped in one move once twice the budget is held: each byte moves once at most.
        if self.kept.len() > self.budget.saturating_mul(2) {
            let excess = self.kept.len().saturating_sub(self.budget);
            self.kept.drain(..excess);
        }
    }

    /// Bytes no longer kept.
    fn dropped(&self) -> u64 {
        self.total
            .saturating_sub(u64::try_from(self.kept.len()).unwrap_or(u64::MAX))
    }

    /// What is kept from byte `at` on (counted from the job's first), at most `max` bytes; and the
    /// bytes dropped before `at`'s place, if `at` was dropped.
    fn read(&self, at: u64, max: usize) -> (u64, &[u8]) {
        let dropped = self.dropped();
        let skipped = dropped.saturating_sub(at);
        let from = usize::try_from(at.max(dropped).saturating_sub(dropped)).unwrap_or(usize::MAX);
        let rest = self.kept.get(from..).unwrap_or_default();
        (skipped, rest.get(..max.min(rest.len())).unwrap_or_default())
    }

    /// Whether `text` is in what is kept from byte `from` on.
    fn find(&self, text: &[u8], from: u64) -> bool {
        let (_, rest) = self.read(from, usize::MAX);
        !text.is_empty() && rest.windows(text.len()).any(|w| w == text)
    }
}

/// How a job stands, published on each change.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Status {
    /// Bytes it wrote.
    pub written: u64,
    /// Its status, once it ended.
    pub exit: Option<u32>,
}

/// One job.
pub struct Job {
    pub name: JobName,
    command: String,
    started: Instant,
    ended: Mutex<Option<Instant>>,
    log: Mutex<Log>,
    status: watch::Sender<Status>,
    signals: mpsc::Sender<Signal>,
}

impl Job {
    /// How it stands, as it changes.
    pub fn watch(&self) -> watch::Receiver<Status> {
        self.status.subscribe()
    }

    /// Whether `text` is in its output from byte `from` on.
    pub fn found(&self, text: &str, from: u64) -> bool {
        self.log
            .lock()
            .is_ok_and(|log| log.find(text.as_bytes(), from))
    }

    fn info(&self, now: Instant) -> JobInfo {
        let status = *self.status.borrow();
        let ended = self.ended.lock().ok().and_then(|e| *e);
        let dropped = self.log.lock().map_or(0, |log| log.dropped());
        JobInfo {
            name: self.name.clone(),
            command: self.command.clone(),
            age_secs: now.saturating_duration_since(self.started).as_secs(),
            ran_secs: ended.map(|at| at.saturating_duration_since(self.started).as_secs()),
            state: status.exit.map_or(JobState::Running, JobState::Exited),
            output_bytes: status.written,
            dropped_bytes: dropped,
        }
    }

    fn running(&self) -> bool {
        self.status.borrow().exit.is_none()
    }

    fn ended_before(&self, cutoff: Instant) -> bool {
        self.ended
            .lock()
            .ok()
            .and_then(|e| *e)
            .is_some_and(|at| at < cutoff)
    }
}

/// Every peer's jobs, by peer and name.
type Table = BTreeMap<(EndpointId, JobName), Arc<Job>>;

/// Every peer's jobs.
#[derive(Clone)]
pub struct Jobs {
    table: Arc<Mutex<Table>>,
    /// The bytes of output each keeps.
    log_bytes: usize,
    /// How long an ended job is kept.
    ttl: Duration,
}

impl Jobs {
    pub fn new(log_bytes: usize, ttl: Duration) -> Self {
        Self {
            table: Arc::default(),
            log_bytes,
            ttl,
        }
    }

    /// `peer`'s job `name`.
    pub fn get(&self, peer: EndpointId, name: &JobName) -> Option<Arc<Job>> {
        let table = self.table.lock().ok()?;
        table.get(&(peer, name.clone())).cloned()
    }

    /// `peer`'s jobs, oldest first.
    pub fn list(&self, peer: EndpointId) -> JobList {
        let now = Instant::now();
        let mut jobs: Vec<Arc<Job>> = self.table.lock().map_or_else(
            |_| Vec::new(),
            |table| {
                table
                    .iter()
                    .filter(|((owner, _), _)| *owner == peer)
                    .map(|(_, job)| Arc::clone(job))
                    .collect()
            },
        );
        jobs.sort_by_key(|job| job.started);
        JobList(jobs.iter().map(|job| job.info(now)).collect())
    }

    /// Start `run` at `place` as `peer`'s job `name` (else the next number free).
    pub fn start(
        &self,
        peer: EndpointId,
        name: Option<JobName>,
        run: &Run,
        host: &Host,
        place: &Place,
    ) -> Result<Started, Problem> {
        let mut table = self
            .table
            .lock()
            .map_err(|_poisoned| Problem::new(ProblemKind::Failed, "the job table"))?;
        let now = Instant::now();
        // Ended jobs past their time go.
        if let Some(cutoff) = now.checked_sub(self.ttl) {
            table.retain(|_, job| !job.ended_before(cutoff));
        }
        let name = match name {
            Some(name) => name,
            None => (1_u64..)
                .take(MAX_JOBS.saturating_add(1))
                .filter_map(|n| JobName::new(&n.to_string()).ok())
                .find(|name| !table.contains_key(&(peer, name.clone())))
                .ok_or_else(|| Problem::new(ProblemKind::TooManyJobs, ""))?,
        };
        match table.get(&(peer, name.clone())) {
            Some(job) if job.running() => return Err(Problem::new(ProblemKind::NameTaken, &name)),
            Some(_) => drop(table.remove(&(peer, name.clone()))),
            None => {}
        }
        if table.len() >= MAX_JOBS {
            // Room is made from the oldest ended job.
            let oldest = table
                .iter()
                .filter(|(_, job)| !job.running())
                .min_by_key(|(_, job)| job.started)
                .map(|(key, _)| key.clone());
            match oldest {
                Some(key) => drop(table.remove(&key)),
                None => return Err(Problem::new(ProblemKind::TooManyJobs, "")),
            }
        }
        let (process, _, stdout, stderr) = super::exec::spawn(run, host, place, false)?;
        let (signals, signals_rx) = mpsc::channel(4);
        let job = Arc::new(Job {
            name: name.clone(),
            command: run.command.display(),
            started: now,
            ended: Mutex::new(None),
            log: Mutex::new(Log {
                budget: self.log_bytes,
                ..Log::default()
            }),
            status: watch::channel(Status::default()).0,
            signals,
        });
        table.insert((peer, name.clone()), Arc::clone(&job));
        #[expect(
            clippy::disallowed_methods,
            reason = "a job's runner, one a job: at most `MAX_JOBS` run"
        )]
        tokio::spawn(runner(
            job,
            process,
            (stdout, stderr),
            signals_rx,
            host.shutdown.clone(),
        ));
        Ok(Started { name })
    }

    /// Send `peer`'s job `name` `signal`.
    pub fn kill(&self, peer: EndpointId, name: &JobName, signal: Signal) -> Result<(), Problem> {
        let job = self
            .get(peer, name)
            .ok_or_else(|| Problem::new(ProblemKind::NoSuchJob, name))?;
        if !job.running() {
            return Ok(());
        }
        job.signals
            .try_send(signal)
            .map_err(|_full| Problem::new(ProblemKind::Failed, "signals are waiting for that job"))
    }
}

/// Run `job`'s `process`: its output into the log, its signals to it, its end into its status.
async fn runner(
    job: Arc<Job>,
    mut process: super::exec::Process,
    (mut stdout, mut stderr): (tokio::process::ChildStdout, tokio::process::ChildStderr),
    mut signals: mpsc::Receiver<Signal>,
    shutdown: tokio_util::sync::CancellationToken,
) {
    let (mut out_buf, mut err_buf) = (vec![0u8; 16 * 1024], vec![0u8; 16 * 1024]);
    let (mut out_done, mut err_done) = (false, false);
    let mut exit: Option<(u32, Instant)> = None;
    let append = |bytes: &[u8]| {
        if let Ok(mut log) = job.log.lock() {
            log.append(bytes);
            let total = log.total;
            job.status.send_modify(|s| s.written = total);
        }
    };
    let code = loop {
        if let Some((code, at)) = exit {
            if (out_done && err_done) || at.elapsed() >= DRAINED {
                break code;
            }
        }
        tokio::select! {
            read = stdout.read(&mut out_buf), if !out_done => match read {
                Ok(n) if n > 0 => append(out_buf.get(..n).unwrap_or_default()),
                Ok(_) | Err(_) => out_done = true,
            },
            read = stderr.read(&mut err_buf), if !err_done => match read {
                Ok(n) if n > 0 => append(err_buf.get(..n).unwrap_or_default()),
                Ok(_) | Err(_) => err_done = true,
            },
            Some(signal) = signals.recv() => process.signal(match signal {
                Signal::Term => fuxix::process::Signal::Term,
                Signal::Kill => fuxix::process::Signal::Kill,
                Signal::Int => fuxix::process::Signal::Int,
                Signal::Hup => fuxix::process::Signal::Hup,
            }),
            () = tokio::time::sleep(EXIT_POLL), if exit.is_none() => {
                exit = process.exit().map(|code| (code, Instant::now()));
            }
            () = tokio::time::sleep(DRAINED), if exit.is_some() => {}
            () = shutdown.cancelled() => {
                drop(process);
                break HUNG_UP;
            }
        }
    };
    if let Ok(mut ended) = job.ended.lock() {
        *ended = Some(Instant::now());
    }
    job.status.send_modify(|s| s.exit = Some(code));
}

/// Send `job`'s log on a stream of `conn`'s: what is kept, then, if `follow`, what it writes
/// until it ends; then the end. The connection's end stops it.
pub async fn logs(conn: &iroh::endpoint::Connection, job: &Job, follow: bool) {
    let sent = async {
        let mut send = conn.open_uni().await?;
        let mut status = job.watch();
        let mut at: u64 = 0;
        loop {
            let now = *status.borrow_and_update();
            // What is there to send now, a chunk at a time.
            loop {
                let (skipped, chunk) = match job.log.lock() {
                    Ok(log) => {
                        let (skipped, chunk) = log.read(at, MAX_LOG_CHUNK);
                        (skipped, chunk.to_vec())
                    }
                    Err(_) => (0, Vec::new()),
                };
                if skipped > 0 {
                    at = at.saturating_add(skipped);
                    send_msg(&mut send, &LogMsg::Dropped(skipped)).await?;
                }
                if chunk.is_empty() {
                    break;
                }
                at = at.saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
                send_msg(&mut send, &LogMsg::Data(chunk)).await?;
            }
            if now.exit.is_some() && at >= now.written {
                send_msg(&mut send, &LogMsg::End(now.exit)).await?;
                break;
            }
            if !follow {
                send_msg(&mut send, &LogMsg::End(None)).await?;
                break;
            }
            tokio::select! {
                changed = status.changed() => changed?,
                _ = conn.closed() => return anyhow::Ok(()),
            }
        }
        send.finish()?;
        anyhow::Ok(())
    };
    if sent.await.is_ok() {
        super::linger(conn).await;
    }
}

async fn send_msg(send: &mut iroh::endpoint::SendStream, msg: &LogMsg) -> anyhow::Result<()> {
    let bytes = crate::request::encode(msg, MAX_LOG_CHUNK.saturating_add(64))?;
    send.write_all(&bytes).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::Log;

    #[test]
    fn a_log_keeps_its_newest_bytes_and_says_how_many_went() {
        let mut log = Log {
            budget: 10,
            ..Log::default()
        };
        log.append(b"0123456789");
        assert_eq!(log.read(0, 100), (0, &b"0123456789"[..]));
        log.append(b"abcdefghijk");
        // Past twice the budget: the newest ten are kept, eleven dropped.
        assert_eq!(log.dropped(), 11);
        assert_eq!(log.read(0, 100), (11, &b"abcdefghijk"[1..]));
        assert_eq!(log.read(15, 3), (0, &b"fgh"[..]));
        assert!(log.find(b"hij", 0));
        assert!(!log.find(b"012", 0), "dropped");
        assert!(!log.find(b"cde", 15), "before where the search starts");
        assert_eq!(log.read(21, 10), (0, &b""[..]));
    }
}
