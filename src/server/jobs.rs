//! Jobs (`koh run`): commands with no terminal that outlive the connection that started them,
//! their output and status kept.
//!
//! A job is a peer's, by name: given, or the next number. Its stdout and stderr are one pipe, so
//! they go into its log in the order it wrote them: a log of at most `job_log_bytes`, the oldest
//! dropped past it (and counted); its stdin is `/dev/null`. It runs until it exits, is signalled
//! (`koh kill`), its peer is removed from the allowlist, or the server stops, which hang it up. A
//! job that ended is kept, with its log and status, until its name is used again, room is needed
//! for a new one, or the session TTL has passed since it ended.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use iroh::EndpointId;
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use super::cli::Host;
use super::exec::{Drain, Spawned};
use super::place::Place;
use crate::request::{
    JobInfo, JobList, JobName, JobState, LogMsg, Problem, ProblemKind, Run, Signal, Started, Usage,
    MAX_COMMAND, MAX_LOG_CHUNK, MAX_TITLE,
};

/// Most jobs kept, all peers', running and ended together.
pub const MAX_JOBS: usize = 64;

/// The status of a job hung up by the server's shutdown, as one hung up by its terminal.
const HUNG_UP: u32 = 128 + 1;

/// The status of a job that did not start, as a shell says of a command it cannot run.
const NOT_STARTED: u32 = 127;

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

    /// Where its last `lines` lines begin (counted from the job's first byte), and how many lines
    /// of what is kept go before them. A last line with no newline yet is one.
    fn tail(&self, lines: u32) -> (u64, u64) {
        let body = self.kept.strip_suffix(b"\n").unwrap_or(&self.kept);
        // Just past the newline that ends the line before them.
        let from = match lines.checked_sub(1) {
            None => self.kept.len(),
            Some(newer) => body
                .iter()
                .enumerate()
                .rev()
                .filter(|&(_, &b)| b == b'\n')
                .nth(usize::try_from(newer).unwrap_or(usize::MAX))
                .map_or(0, |(at, _)| at.saturating_add(1)),
        };
        let before = self.kept.get(..from).unwrap_or_default();
        let before = before.split(|&b| b == b'\n').skip(1).count();
        (
            self.dropped()
                .saturating_add(u64::try_from(from).unwrap_or(u64::MAX)),
            u64::try_from(before).unwrap_or(u64::MAX),
        )
    }
}

/// How a job stands, published on each change.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Status {
    /// Bytes it wrote.
    pub written: u64,
    /// Its status, once it ended, and when.
    pub exit: Option<u32>,
    ended: Option<Instant>,
}

/// One job.
pub struct Job {
    name: JobName,
    command: String,
    /// The session it leads, by its pid, once it started.
    session: OnceLock<i32>,
    started: Instant,
    log: Mutex<Log>,
    status: watch::Sender<Status>,
    signals: mpsc::Sender<Signal>,
    /// Hangs it up: its peer was removed, or the server is stopping.
    stop: CancellationToken,
}

impl Job {
    /// How it stands, as it changes.
    pub fn watch(&self) -> watch::Receiver<Status> {
        self.status.subscribe()
    }

    /// Whether `text` is in its output from byte `*from` on; `*from` moves on past where it could
    /// now begin, so a search again looks only at what came since. The log is held only to copy.
    pub fn find(&self, text: &str, from: &mut u64) -> bool {
        let Ok((at, kept)) = self.log.lock().map(|log| {
            let (skipped, kept) = log.read(*from, usize::MAX);
            (from.saturating_add(skipped), kept.to_vec())
        }) else {
            return false;
        };
        let text = text.as_bytes();
        let len = u64::try_from(kept.len()).unwrap_or(u64::MAX);
        let overlap = u64::try_from(text.len().saturating_sub(1)).unwrap_or(u64::MAX);
        *from = at.max(at.saturating_add(len).saturating_sub(overlap));
        !text.is_empty() && kept.windows(text.len()).any(|w| w == text)
    }

    fn append(&self, bytes: &[u8]) {
        let Ok(total) = self.log.lock().map(|mut log| {
            log.append(bytes);
            log.total
        }) else {
            return;
        };
        self.status.send_modify(|s| s.written = total);
    }

    fn end(&self, code: u32) {
        self.status.send_modify(|s| {
            s.exit = Some(code);
            s.ended = Some(Instant::now());
        });
    }

    /// How it stands at `now`, its command whole if `whole`, else cut for a listing; `usage` says
    /// what each session's processes use.
    fn info(&self, now: Instant, whole: bool, usage: Option<&Sessions>) -> JobInfo {
        let status = *self.status.borrow();
        let dropped = self.log.lock().map_or(0, |log| log.dropped());
        JobInfo {
            name: self.name.clone(),
            command: if whole {
                let end = self.command.floor_char_boundary(MAX_COMMAND);
                self.command.get(..end).unwrap_or_default().to_owned()
            } else {
                self.command.chars().take(MAX_TITLE).collect()
            },
            age_secs: now.saturating_duration_since(self.started).as_secs(),
            ran_secs: status
                .ended
                .map(|at| at.saturating_duration_since(self.started).as_secs()),
            state: status.exit.map_or(JobState::Running, JobState::Exited),
            output_bytes: status.written,
            dropped_bytes: dropped,
            usage: (status.exit.is_none())
                .then(|| usage.zip(self.session.get()))
                .flatten()
                .map(|(usage, session)| usage.get(session).copied().unwrap_or_default()),
        }
    }

    /// The seconds it ran, or has run so far.
    fn secs(&self) -> u64 {
        self.status
            .borrow()
            .ended
            .unwrap_or_else(Instant::now)
            .saturating_duration_since(self.started)
            .as_secs()
    }

    fn running(&self) -> bool {
        self.status.borrow().exit.is_none()
    }

    fn ended_before(&self, cutoff: Instant) -> bool {
        self.status.borrow().ended.is_some_and(|at| at < cutoff)
    }
}

/// What each session's processes use, by its leader's pid.
type Sessions = BTreeMap<i32, Usage>;

/// What every session's processes use, as `/proc` says: `None` where there is no `/proc` (macOS).
/// A process's own CPU time and that of its children it waited for count, so a build's compilers
/// that came and went are in it.
fn sessions() -> Option<Sessions> {
    let ticks = rustix::param::clock_ticks_per_second().max(1);
    let mut sessions = Sessions::new();
    for entry in std::fs::read_dir("/proc").ok()?.flatten() {
        let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        // After the program's name, which may hold anything but ends at the last `)`: the state,
        // ppid, pgrp, session, …; utime, stime, cutime and cstime are the 12th to the 15th.
        let Some((_, fields)) = stat.rsplit_once(')') else {
            continue;
        };
        let fields: Vec<&str> = fields.split_whitespace().collect();
        let field = |at: usize| fields.get(at).and_then(|f| f.parse::<i64>().ok());
        let Some(session) = field(3).and_then(|s| i32::try_from(s).ok()) else {
            continue;
        };
        let used = (11..=14).filter_map(field).fold(0_u64, |sum, t| {
            sum.saturating_add(u64::try_from(t).unwrap_or(0))
        });
        let usage = sessions.entry(session).or_default();
        usage.processes = usage.processes.saturating_add(1);
        usage.cpu_ms = usage
            .cpu_ms
            .saturating_add(used.saturating_mul(1000).checked_div(ticks).unwrap_or(0));
    }
    Some(sessions)
}

/// Every peer's jobs, by peer and name.
type Table = BTreeMap<(EndpointId, JobName), Arc<Job>>;

/// Every peer's jobs.
pub struct Jobs {
    table: Mutex<Table>,
    /// The bytes of output each keeps.
    log_bytes: usize,
    /// How long an ended job is kept.
    ttl: Duration,
}

impl Jobs {
    pub fn new(log_bytes: usize, ttl: Duration) -> Self {
        Self {
            table: Mutex::default(),
            log_bytes,
            ttl,
        }
    }

    /// `peer`'s job `name`.
    pub fn get(&self, peer: EndpointId, name: &JobName) -> Option<Arc<Job>> {
        let table = self.table.lock().ok()?;
        table.get(&(peer, name.clone())).cloned()
    }

    /// `peer`'s jobs, oldest first; or the one `only` names, its command whole.
    pub fn list(&self, peer: EndpointId, only: Option<&JobName>) -> Result<JobList, Problem> {
        let now = Instant::now();
        if let Some(name) = only {
            let job = self
                .get(peer, name)
                .ok_or_else(|| Problem::new(ProblemKind::NoSuchJob, name))?;
            return Ok(JobList(vec![job.info(now, true, sessions().as_ref())]));
        }
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
        let usage = sessions();
        Ok(JobList(
            jobs.iter()
                .map(|job| job.info(now, false, usage.as_ref()))
                .collect(),
        ))
    }

    /// Start `run` at `place` as `peer`'s job `name` (else the next number free). Its place in the
    /// table is taken first, then it is started off the table's lock.
    pub async fn start(
        &self,
        peer: EndpointId,
        name: Option<JobName>,
        run: &Run,
        host: &Host,
        place: &Place,
    ) -> Result<Started, Problem> {
        let (job, signals) = self.reserve(peer, name, run, &host.shutdown)?;
        let key = (peer, job.name.clone());
        let spawned = super::exec::spawn(run, host, place, false, true).await;
        let spawned = match spawned {
            Ok(spawned) => spawned,
            Err(problem) => {
                job.end(NOT_STARTED);
                if let Ok(mut table) = self.table.lock() {
                    if table.get(&key).is_some_and(|kept| Arc::ptr_eq(kept, &job)) {
                        table.remove(&key);
                    }
                }
                return Err(problem);
            }
        };
        if let Some(session) = spawned.process.session() {
            let _ = job.session.set(session.as_raw());
        }
        #[expect(
            clippy::disallowed_methods,
            reason = "a job's runner, one a job: at most `MAX_JOBS` run"
        )]
        tokio::spawn(runner(job, spawned, signals));
        Ok(Started { name: key.1 })
    }

    /// Take `peer`'s job `name` (else the next number free) in the table for `run`, room made
    /// from the oldest ended job if need be; hung up by `shutdown` too.
    fn reserve(
        &self,
        peer: EndpointId,
        name: Option<JobName>,
        run: &Run,
        shutdown: &CancellationToken,
    ) -> Result<(Arc<Job>, mpsc::Receiver<Signal>), Problem> {
        let mut table = self
            .table
            .lock()
            .map_err(|_poisoned| Problem::new(ProblemKind::Failed, "the job table"))?;
        let now = Instant::now();
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
        let (signals, signals_rx) = mpsc::channel(4);
        let job = Arc::new(Job {
            name: name.clone(),
            command: run.command.display(),
            session: OnceLock::new(),
            started: now,
            log: Mutex::new(Log {
                budget: self.log_bytes,
                ..Log::default()
            }),
            status: watch::channel(Status::default()).0,
            signals,
            stop: shutdown.child_token(),
        });
        table.insert((peer, name), Arc::clone(&job));
        Ok((job, signals_rx))
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

    /// Hang up and forget `peer`'s jobs: it may no longer connect.
    pub fn end(&self, peer: EndpointId) {
        if let Ok(mut table) = self.table.lock() {
            table.retain(|(owner, _), job| {
                let keep = *owner != peer;
                if !keep {
                    job.stop.cancel();
                }
                keep
            });
        }
    }
}

/// Run `job`, started as `spawned`: its output into the log, `signals` to it, its end into its
/// status.
async fn runner(job: Arc<Job>, spawned: Spawned, mut signals: mpsc::Receiver<Signal>) {
    let Spawned {
        process, stdout, ..
    } = spawned;
    let (exited, told) = watch::channel(false);
    let output = async {
        let mut drain = Drain::new(stdout, told);
        while let Some(bytes) = drain.next().await {
            job.append(bytes);
        }
    };
    let stop = job.stop.cancelled();
    let code = super::exec::finish(process, output, exited, &mut signals, stop).await;
    job.end(code.unwrap_or(HUNG_UP));
}

/// Send `job`'s log on a stream of `conn`'s: what is kept (its last `tail` lines, if given), then,
/// if `follow`, what it writes until it ends; then the end. The connection's end stops it.
pub async fn logs(conn: &iroh::endpoint::Connection, job: &Job, follow: bool, tail: Option<u32>) {
    let sent = async {
        let mut send = conn.open_uni().await?;
        let mut status = job.watch();
        let (mut at, cut) = match (tail, job.log.lock()) {
            (Some(lines), Ok(log)) => log.tail(lines),
            (None, _) | (_, Err(_)) => (0, 0),
        };
        if cut > 0 {
            send_msg(&mut send, &LogMsg::Cut(cut)).await?;
        }
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
            if (now.exit.is_some() && at >= now.written) || !follow {
                let exit = now.exit.filter(|_| at >= now.written);
                send_msg(
                    &mut send,
                    &LogMsg::End {
                        exit,
                        secs: job.secs(),
                    },
                )
                .await?;
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
        assert_eq!(log.read(21, 10), (0, &b""[..]));
    }

    #[test]
    fn a_tail_starts_where_its_lines_do_and_counts_those_before() {
        let mut log = Log {
            budget: 100,
            ..Log::default()
        };
        log.append(b"one\ntwo\nthree\n");
        assert_eq!(log.tail(1), (8, 2));
        assert_eq!(log.tail(2), (4, 1));
        assert_eq!(log.tail(3), (0, 0));
        assert_eq!(log.tail(9), (0, 0));
        assert_eq!(log.tail(0), (14, 3));
        // A line still being written is the last.
        log.append(b"fo");
        assert_eq!(log.tail(1), (14, 3));
        assert_eq!(log.read(14, 10), (0, &b"fo"[..]));
    }
}
