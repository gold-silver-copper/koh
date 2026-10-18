//! The client's commands that dial a server.
//!
//! `koh connect` runs [`run_client`](super::run_client) on the real terminal; the others ask one
//! thing and print what they hear: `sessions`, `output`, `run`, `jobs`, `logs`, `kill` and `wait`.
//! Each says it as text for a person, or as one JSON value with `--json`.

use std::io::Write as _;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::Context;
use iroh::endpoint::{Connection, SendStream};
use iroh::{EndpointId, RelayUrl};
use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio_util::sync::CancellationToken;

use crate::client::{refusal, Admitted, DefaultBackend, IrohConnector, KohBackend as _, Refused};
use crate::proto::Close;
use crate::request::{
    Answer, JobInfo, JobList, JobName, JobState, LogMsg, Pick, Presence, Problem, Request, Run,
    SessionInfo, SessionList, SessionNum, Signal, Started, Until, Wait, Waited, MAX_LOG_CHUNK,
    MAX_OUTPUT, MAX_REPLY,
};
use crate::transport_iroh::{bind_on, close_endpoint, Idle, Network};

/// How long the first dial may take.
const DIAL_TIMEOUT: Duration = Duration::from_secs(15);

/// The server a command dials, and how.
#[derive(Debug, Clone)]
pub struct Remote {
    /// Server endpoint id to connect to.
    pub server: EndpointId,
    /// The secret-key file; `None` for the default client key path.
    pub key_file: Option<PathBuf>,
    /// Dial this socket address directly, with no relay or discovery; wins over `relay_url`.
    pub direct: Option<SocketAddr>,
    /// Dial through a self-hosted relay instead of n0's.
    pub relay_url: Option<RelayUrl>,
}

impl Remote {
    /// `server`, dialed through n0's relays and discovery, as the default client key.
    pub const fn new(server: EndpointId) -> Self {
        Self {
            server,
            key_file: None,
            direct: None,
            relay_url: None,
        }
    }
}

/// The clap-free form of `koh connect`'s arguments.
#[derive(Debug, Clone)]
pub struct ConnectConfig {
    pub remote: Remote,
    /// Which of this client's sessions to attach to.
    pub pick: Pick,
    /// Let the server set the clipboard (OSC 52); on unless `--no-clipboard`.
    pub clipboard: bool,
    /// Show the server's hyperlinks (OSC 8); on unless `--no-hyperlinks`.
    pub hyperlinks: bool,
    /// Ask the user's terminal its colours and tell the server, which answers programs' colour
    /// queries with them; on unless `--no-colours`.
    pub colours: bool,
    /// A shell command to run on the remote bell (see [`BellHook`]).
    pub bell_command: Option<String>,
}

impl ConnectConfig {
    /// A config for dialing `server` with every other option at the CLI default.
    pub const fn new(server: EndpointId) -> Self {
        Self {
            remote: Remote::new(server),
            pick: Pick::Latest,
            clipboard: true,
            hyperlinks: true,
            colours: true,
            bell_command: None,
        }
    }
}

/// Runs a command (`sh -c`) when the remote bell rings (`--on-bell`), at most once a second.
///
/// The command is detached, with its stdio on `/dev/null`, `KOH_BELL_COUNT` and `KOH_TITLE` set
/// and every other `KOH_*` variable scrubbed. Only bells that ring while the client is attached
/// reach it, the ones during a reconnect included.
#[derive(Debug, Clone)]
pub struct BellHook {
    command: String,
    last_count: u64,
    last_spawn: Option<Instant>,
}

/// Minimum spacing between two hook spawns; a burst of bells inside it coalesces into one.
pub const BELL_HOOK_MIN_INTERVAL: Duration = Duration::from_secs(1);

impl BellHook {
    pub fn new(command: impl Into<String>) -> Self {
        Self {
            command: command.into(),
            last_count: 0,
            last_spawn: None,
        }
    }

    /// Take `count` as what was rung before: only rises past it ring.
    pub const fn prime(&mut self, count: u64) {
        self.last_count = count;
    }

    /// Note the bell count at `now`; whether to fire: it rose, and the last spawn was at least
    /// [`BELL_HOOK_MIN_INTERVAL`] ago. A rise within that is absorbed, not deferred.
    pub fn observe(&mut self, count: u64, now: Instant) -> bool {
        let rose = count > std::mem::replace(&mut self.last_count, count);
        let spaced = rose
            && self
                .last_spawn
                .is_none_or(|at| now.saturating_duration_since(at) >= BELL_HOOK_MIN_INTERVAL);
        if spaced {
            self.last_spawn = Some(now);
        }
        spaced
    }

    /// The command to spawn, with `parent_env` scrubbed of `KOH_*` (given, so tests can pass their
    /// own).
    pub(crate) fn command(
        &self,
        count: u64,
        title: &str,
        parent_env: impl IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
    ) -> std::process::Command {
        #[expect(
            clippy::disallowed_methods,
            reason = "the user's own --on-bell command"
        )]
        let mut cmd = std::process::Command::new("sh");
        cmd.arg("-c").arg(&self.command).env_clear();
        for (k, v) in parent_env {
            if !crate::pty::is_koh_env_key(&k) {
                cmd.env(k, v);
            }
        }
        cmd.env("KOH_BELL_COUNT", count.to_string())
            .env("KOH_TITLE", title)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        cmd
    }

    /// Spawn the command, reaped on a thread of its own so it can never block the session.
    pub fn fire(&self, count: u64, title: &str) {
        match self.command(count, title, std::env::vars_os()).spawn() {
            Ok(mut child) => {
                let reaper = std::thread::Builder::new()
                    .name("koh-bell-hook".into())
                    .spawn(move || {
                        let _ = child.wait();
                    });
                if let Err(e) = reaper {
                    tracing::warn!(error = %e, "bell hook reaper thread spawn failed");
                }
            }
            Err(e) => tracing::warn!(error = %e, "bell hook spawn failed"),
        }
    }
}

/// Bind an endpoint to dial `remote` from, as `identity`, its connections idle at most as `idle`
/// says, and the connector that dials it.
async fn connector(
    remote: &Remote,
    identity: &crate::identity::Identity,
    idle: Idle,
) -> anyhow::Result<(iroh::Endpoint, IrohConnector)> {
    let secret = identity.secret.clone();
    let server = remote.server;
    let (network, target) = match (remote.direct, remote.relay_url.clone()) {
        (Some(addr), _) => (
            Network::Local,
            iroh::EndpointAddr::new(server).with_ip_addr(addr),
        ),
        (None, Some(relay)) => (
            Network::Relay(relay.clone()),
            iroh::EndpointAddr::new(server).with_relay_url(relay),
        ),
        (None, None) => (Network::N0, server.into()),
    };
    let endpoint = bind_on(secret, (false, idle), &network, None).await?;
    let connector = IrohConnector::new(endpoint.clone(), target);
    Ok((endpoint, connector))
}

/// `koh: could not reach the server`: the error for a dial that timed out.
#[derive(Debug, thiserror::Error)]
#[error("timed out connecting (server unreachable or not responding)")]
pub struct Unreached;

/// `future`, the first dial, within [`DIAL_TIMEOUT`]; failing, `endpoint` is closed.
async fn first_dial<T>(
    endpoint: &iroh::Endpoint,
    future: impl std::future::Future<Output = anyhow::Result<T>>,
) -> anyhow::Result<T> {
    let first = match tokio::time::timeout(DIAL_TIMEOUT, future).await {
        Ok(first) => first,
        Err(_) => Err(Unreached.into()),
    };
    if first.is_err() {
        let _ = close_endpoint(endpoint).await;
    }
    first
}

/// One connection to a server for one request: a command's, a copy's or a question's.
pub(crate) struct Opened {
    pub(crate) conn: Connection,
    /// The client's first stream, the request on it, open for what follows.
    pub(crate) control: SendStream,
    endpoint: iroh::Endpoint,
    /// Held while connected: its lease stops `koh key reset`.
    _identity: crate::identity::Identity,
}

impl Opened {
    /// Dial `remote` as its client key and make `request`. Its connection is a command's: a
    /// client killed where it stands is noticed within 20 seconds, and what it ran hung up.
    pub(crate) async fn dial(remote: &Remote, request: &Request) -> anyhow::Result<Self> {
        log_to_koh_log();
        let identity = crate::identity::load(&crate::identity::KeyFile::locate(
            remote.key_file.clone(),
            "client",
        )?)?;
        let (endpoint, connector) = connector(remote, &identity, Idle::Command).await?;
        let (conn, control) = first_dial(&endpoint, connector.open(request)).await?;
        Ok(Self {
            conn,
            control,
            endpoint,
            _identity: identity,
        })
    }

    /// Done: close the connection, telling the server at once.
    pub(crate) async fn close(self) {
        self.conn.close(0u32.into(), b"done");
        let _ = close_endpoint(&self.endpoint).await;
    }

    /// The answer on the server's next stream, at most `max` bytes: what was asked, or why not.
    async fn answer<T: DeserializeOwned>(&self, max: usize) -> anyhow::Result<T> {
        let read = async {
            let mut recv = self.conn.accept_uni().await?;
            let bytes = recv.read_to_end(max.saturating_add(4)).await?;
            anyhow::Ok(crate::request::decode_framed::<Answer<T>>(&bytes, max)?)
        };
        match read.await {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(problem)) => Err(problem.into()),
            Err(error) => Err(refusal(&self.conn, &error)),
        }
    }
}

/// Make `request` of `remote` and take its answer, at most `max` bytes.
async fn ask<T: DeserializeOwned>(
    remote: &Remote,
    request: &Request,
    max: usize,
) -> anyhow::Result<T> {
    let mut opened = Opened::dial(remote, request).await?;
    opened.control.finish()?;
    let answer = opened.answer(max).await;
    opened.close().await;
    answer
}

/// The exit status for a koh error: 3 the server was not reached, 4 it refused this client for
/// good (or its key's scope), 1 anything else.
pub fn exit_code(error: &anyhow::Error) -> u8 {
    if error.is::<Unreached>() || error.downcast_ref::<Close>() == Some(&Close::AtCapacity) {
        3
    } else if error.is::<Refused>() {
        4
    } else {
        1
    }
}

/// What a koh error says in `--json` output: its kind, and its words.
pub fn json_error(error: &anyhow::Error) -> String {
    #[derive(Serialize)]
    struct Inner<'a> {
        kind: &'a str,
        message: String,
    }
    #[derive(Serialize)]
    struct View<'a> {
        error: Inner<'a>,
    }
    let kind = if error.is::<Unreached>() {
        "unreached"
    } else if let Some(refused) = error.downcast_ref::<Refused>() {
        match refused {
            Refused::NotAuthorized => "not_authorized",
            Refused::NoSuchSession => "no_such_session",
            Refused::OutOfScope => "out_of_scope",
            Refused::OtherProtocol => "other_protocol",
        }
    } else if let Some(problem) = error.downcast_ref::<Problem>() {
        problem.kind.name()
    } else if let Some(failure) = error.downcast_ref::<crate::sync::Failure>() {
        failure.kind.name()
    } else {
        "failed"
    };
    let view = View {
        error: Inner {
            kind,
            message: format!("{error:#}"),
        },
    };
    serde_json::to_string(&view).unwrap_or_default()
}

/// How a command says what it heard.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Format {
    pub json: bool,
}

/// Write `value` as one line of JSON to `out`.
fn json_line(out: &mut impl std::io::Write, value: &impl Serialize) -> anyhow::Result<()> {
    serde_json::to_writer(&mut *out, value)?;
    writeln!(out)?;
    Ok(())
}

/// A session, as `koh sessions --json` says it.
#[derive(Serialize)]
struct SessionView {
    session: u64,
    attached: bool,
    detached_secs: Option<u64>,
    age_secs: u64,
    rows: u16,
    cols: u16,
    title: String,
    exited: Option<u32>,
    activity: Option<&'static str>,
    command_running: bool,
    commands_finished: u64,
    last_status: Option<i32>,
}

impl From<&SessionInfo> for SessionView {
    fn from(info: &SessionInfo) -> Self {
        let detached_secs = match info.presence {
            Presence::Attached => None,
            Presence::Detached { secs } => Some(secs),
        };
        Self {
            session: info.session.0,
            attached: detached_secs.is_none(),
            detached_secs,
            age_secs: info.age_secs,
            rows: info.size.rows,
            cols: info.size.cols,
            title: info.title.clone(),
            exited: info.exited,
            activity: info.state.activity.map(crate::terminal::Activity::name),
            command_running: info.state.running,
            commands_finished: info.state.finished,
            last_status: info.state.last_status,
        }
    }
}

/// `koh sessions`: this client's sessions on `remote`, one a line, to `out`.
pub async fn sessions(
    remote: &Remote,
    format: Format,
    out: &mut impl std::io::Write,
) -> anyhow::Result<()> {
    let SessionList(listed) = ask(remote, &Request::Sessions, MAX_REPLY).await?;
    if format.json {
        let views: Vec<SessionView> = listed.iter().map(SessionView::from).collect();
        return json_line(out, &views);
    }
    if listed.is_empty() {
        writeln!(out, "no sessions")?;
    }
    for info in listed {
        writeln!(out, "{}", listing(&info))?;
    }
    Ok(())
}

/// Text a program chose, safe to print on a line: nothing in it may move the cursor or reorder
/// the line.
pub(crate) fn escaped(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c == ' ' || !(c.is_control() || c.is_whitespace() || crate::log::is_bidi(c)) {
            out.push(c);
        } else {
            out.extend(c.escape_default());
        }
    }
    out
}

/// One session as `koh sessions` lists it: space-separated fields, none holding a space, then the
/// title, escaped, to the line's end: `3 detached=5m age=2h01m 80x24 reading done=1 vim notes`.
fn listing(info: &SessionInfo) -> String {
    let presence = match info.presence {
        Presence::Attached => "attached".to_owned(),
        Presence::Detached { secs } => format!("detached={}", span(secs)),
    };
    let program = match (info.exited, info.state.running, info.state.activity) {
        (Some(code), _, _) => format!("exited={code}"),
        (None, true, activity) => format!(
            "running:{}",
            activity.map_or("unknown", crate::terminal::Activity::name)
        ),
        (None, false, activity) => activity
            .map_or("unknown", crate::terminal::Activity::name)
            .to_owned(),
    };
    let last = info
        .state
        .last_status
        .map_or_else(String::new, |status| format!(" last={status}"));
    format!(
        "{} {presence} age={} {}x{} {program}{last} {}",
        info.session,
        span(info.age_secs),
        info.size.cols,
        info.size.rows,
        escaped(&info.title),
    )
    .trim_end()
    .to_owned()
}

/// `secs` in its two largest units: `45s`, `3m12s`, `2h05m`, `4d03h`.
fn span(secs: u64) -> String {
    let (m, h, d) = (
        secs.div_euclid(60),
        secs.div_euclid(3600),
        secs.div_euclid(86_400),
    );
    if d > 0 {
        format!("{d}d{:02}h", h.rem_euclid(24))
    } else if h > 0 {
        format!("{h}h{:02}m", m.rem_euclid(60))
    } else if m > 0 {
        format!("{m}m{:02}s", secs.rem_euclid(60))
    } else {
        format!("{secs}s")
    }
}

/// `koh output`: session `session`'s screen, or the last command's output if `last`, to `out`.
pub async fn output(
    remote: &Remote,
    (session, last): (SessionNum, bool),
    format: Format,
    out: &mut impl std::io::Write,
) -> anyhow::Result<()> {
    let text: String = ask(remote, &Request::Output { session, last }, MAX_OUTPUT).await?;
    if format.json {
        #[derive(Serialize)]
        struct View<'a> {
            session: u64,
            text: &'a str,
        }
        return json_line(
            out,
            &View {
                session: session.0,
                text: &text,
            },
        );
    }
    out.write_all(text.as_bytes())?;
    Ok(())
}

/// A job, as `koh jobs --json` says it.
#[derive(Serialize)]
struct JobView<'a> {
    name: &'a str,
    command: &'a str,
    running: bool,
    status: Option<u32>,
    age_secs: u64,
    ran_secs: Option<u64>,
    output_bytes: u64,
    dropped_bytes: u64,
}

impl<'a> From<&'a JobInfo> for JobView<'a> {
    fn from(job: &'a JobInfo) -> Self {
        let status = match job.state {
            JobState::Running => None,
            JobState::Exited(code) => Some(code),
        };
        Self {
            name: job.name.as_str(),
            command: &job.command,
            running: status.is_none(),
            status,
            age_secs: job.age_secs,
            ran_secs: job.ran_secs,
            output_bytes: job.output_bytes,
            dropped_bytes: job.dropped_bytes,
        }
    }
}

/// `koh run`: start `run` as job `name` on `remote`; its name, to `out`.
pub async fn run(
    remote: &Remote,
    (name, run): (Option<JobName>, Run),
    format: Format,
    out: &mut impl std::io::Write,
) -> anyhow::Result<()> {
    let Started { name } = ask(remote, &Request::Start { name, run }, MAX_REPLY).await?;
    if format.json {
        #[derive(Serialize)]
        struct View<'a> {
            job: &'a str,
        }
        return json_line(out, &View { job: name.as_str() });
    }
    writeln!(out, "{name}")?;
    Ok(())
}

/// `koh jobs`: this client's jobs on `remote`, one a line, to `out`.
pub async fn jobs(
    remote: &Remote,
    job: Option<JobName>,
    format: Format,
    out: &mut impl std::io::Write,
) -> anyhow::Result<()> {
    let by_name = job.is_some();
    let JobList(jobs) = ask(remote, &Request::Jobs { job }, MAX_REPLY).await?;
    if format.json {
        let views: Vec<JobView<'_>> = jobs.iter().map(JobView::from).collect();
        return json_line(out, &views);
    }
    if jobs.is_empty() {
        writeln!(out, "no jobs")?;
    }
    for job in &jobs {
        let state = match job.state {
            JobState::Running => format!("running {}", span(job.age_secs)),
            JobState::Exited(code) => format!(
                "exited={code} after {} ({} ago)",
                span(job.ran_secs.unwrap_or_default()),
                span(
                    job.age_secs
                        .saturating_sub(job.ran_secs.unwrap_or_default())
                )
            ),
        };
        let dropped = if job.dropped_bytes > 0 {
            format!(", {} dropped", bytes(job.dropped_bytes))
        } else {
            String::new()
        };
        let head = format!(
            "{} {state} output={}{dropped}",
            job.name,
            bytes(job.output_bytes)
        );
        if by_name {
            // The command whole, on the lines after, as it was given.
            writeln!(out, "{head}")?;
            for line in job.command.lines() {
                writeln!(out, "  {}", escaped(line))?;
            }
        } else {
            writeln!(out, "{head} {}", first_line(&job.command))?;
        }
    }
    Ok(())
}

/// Most characters of a command a job listing shows.
const LISTED_COMMAND: usize = 60;

/// `command`'s first line, escaped, cut to [`LISTED_COMMAND`] characters: ` …` marks a cut, or
/// lines after it (`koh jobs SERVER NAME` shows it whole).
fn first_line(command: &str) -> String {
    let mut lines = command.lines();
    let first = lines.next().unwrap_or_default();
    let shown: String = first.chars().take(LISTED_COMMAND).collect();
    let cut = shown.len() < first.len() || lines.next().is_some();
    format!("{}{}", escaped(&shown), if cut { " …" } else { "" })
}

/// `bytes` for a person: `41 KB`, `1.2 MB`.
pub fn bytes(n: u64) -> String {
    let n = u128::from(n);
    let (unit, scale) = match n {
        0..=999 => return format!("{n} B"),
        1_000..=999_999 => ("KB", 1_000),
        1_000_000..=999_999_999 => ("MB", 1_000_000),
        _ => ("GB", 1_000_000_000),
    };
    let tenths = n.saturating_mul(10).checked_div(scale).unwrap_or(0);
    let (whole, tenth) = (tenths.div_euclid(10), tenths.rem_euclid(10));
    if whole >= 10 || tenth == 0 {
        format!("{whole} {unit}")
    } else {
        format!("{whole}.{tenth} {unit}")
    }
}

/// `koh logs`: job `job`'s output to `out`, and with `follow` what it writes until it ends; its
/// status if it ended (then koh exits with it), `None` if it runs on.
pub async fn logs(remote: &Remote, job: JobName, follow: bool) -> anyhow::Result<Option<u32>> {
    let interrupted = CancellationToken::new();
    crate::cancel_on_signals(&interrupted)?;
    let mut opened = Opened::dial(remote, &Request::Logs { job, follow }).await?;
    opened.control.finish()?;
    let read = async {
        let mut recv = opened.conn.accept_uni().await?;
        let mut stdout = tokio::io::stdout();
        loop {
            let body =
                crate::transport_iroh::read_framed(&mut recv, MAX_LOG_CHUNK.saturating_add(64))
                    .await?;
            // A job the server does not have answers as a problem instead.
            if let Ok(Err(problem)) = crate::request::decode::<Answer<()>>(&body) {
                return Err(problem.into());
            }
            match crate::request::decode::<LogMsg>(&body)? {
                LogMsg::Dropped(n) => crate::log::stderr(format_args!(
                    "koh: {} of the job's output were dropped before this (the log keeps its newest)",
                    bytes(n)
                )),
                LogMsg::Data(data) => {
                    use tokio::io::AsyncWriteExt as _;
                    stdout.write_all(&data).await?;
                    stdout.flush().await?;
                }
                LogMsg::End(status) => return anyhow::Ok(status),
            }
        }
    };
    let status = tokio::select! {
        status = read => status.map_err(|e| match e.downcast::<Problem>() {
            Ok(problem) => problem.into(),
            Err(e) => refusal(&opened.conn, &e),
        }),
        () = interrupted.cancelled() => Ok(None),
    };
    opened.close().await;
    status
}

/// `koh kill`: send job `job` on `remote` `signal`.
pub async fn kill(
    remote: &Remote,
    (job, signal): (JobName, Signal),
    format: Format,
    out: &mut impl std::io::Write,
) -> anyhow::Result<()> {
    ask::<()>(
        remote,
        &Request::Kill {
            job: job.clone(),
            signal,
        },
        MAX_REPLY,
    )
    .await?;
    if format.json {
        #[derive(Serialize)]
        struct View<'a> {
            job: &'a str,
            signalled: bool,
        }
        return json_line(
            out,
            &View {
                job: job.as_str(),
                signalled: true,
            },
        );
    }
    Ok(())
}

/// The status `koh wait` exits with when it gave up waiting: `timeout`'s.
pub const TIMED_OUT: u32 = 124;

/// `koh wait`: wait on `remote` as `wait` says, at most `timeout`.
///
/// The status to exit with: the job's or the command's for an end, 0 for what was waited for, 1 if
/// the job ended without it, [`TIMED_OUT`] past the time. On a terminal it reports `busy` while it
/// waits.
pub async fn wait(
    remote: &Remote,
    (wait, timeout): (Wait, Option<Duration>),
    format: Format,
    out: &mut impl std::io::Write,
) -> anyhow::Result<u32> {
    let interrupted = CancellationToken::new();
    crate::cancel_on_signals(&interrupted)?;
    let until = wait.until.clone();
    report_busy();
    let waited = async { ask::<Waited>(remote, &Request::Wait(wait), MAX_REPLY).await };
    let waited = tokio::select! {
        waited = waited => Some(waited?),
        () = sleep_for(timeout) => None,
        () = interrupted.cancelled() => anyhow::bail!("interrupted"),
    };
    let (status, said) = match (waited, &until) {
        (None, _) => (TIMED_OUT, "timed out".to_owned()),
        (Some(Waited::Ended(status)), Until::End) => {
            let code = status.map_or(0, |s| u32::try_from(s & 0xff).unwrap_or(1));
            (
                code,
                status.map_or_else(|| "ended".to_owned(), |s| format!("ended with status {s}")),
            )
        }
        (Some(Waited::Ended(status)), Until::Text(_) | Until::File(_) | Until::Reading) => (
            1,
            status.map_or_else(
                || "ended before it came".to_owned(),
                |s| format!("ended with status {s} before it came"),
            ),
        ),
        (Some(Waited::Text), _) => (0, "the text appeared".to_owned()),
        (Some(Waited::File), _) => (0, "the file appeared".to_owned()),
        (Some(Waited::Reading), _) => (0, "reading its terminal".to_owned()),
    };
    if format.json {
        #[derive(Serialize)]
        struct View<'a> {
            status: u32,
            waited: &'a str,
            timed_out: bool,
        }
        json_line(
            out,
            &View {
                status,
                waited: &said,
                timed_out: status == TIMED_OUT,
            },
        )?;
    } else if status == TIMED_OUT || (status == 1 && !matches!(until, Until::End)) {
        crate::log::stderr(format_args!("koh: {said}"));
    }
    Ok(status)
}

async fn sleep_for(timeout: Option<Duration>) {
    match timeout {
        Some(timeout) => tokio::time::sleep(timeout).await,
        None => std::future::pending().await,
    }
}

/// Tell a terminal that reads state reports (fux) that koh is busy: it waits on the server, not
/// on input. Only when stdout is a terminal, with the nonce the terminal asks for.
pub fn report_busy() {
    use std::io::IsTerminal as _;
    let stdout = std::io::stdout();
    if !stdout.is_terminal() {
        return;
    }
    let nonce = crate::client::backend::MarkNonce::from_env();
    let report = match nonce {
        Some(nonce) => format!("\x1b]133;S;activity=busy;nonce={}\x07", nonce.as_str()),
        None => "\x1b]133;S;activity=busy\x07".to_owned(),
    };
    let mut stdout = stdout.lock();
    let _ = stdout.write_all(report.as_bytes());
    let _ = stdout.flush();
}

/// Warn if the locale does not look UTF-8, which koh assumes; mosh refuses to run instead.
fn warn_if_locale_not_utf8() {
    // In POSIX's order of precedence.
    let locale = ["LC_ALL", "LC_CTYPE", "LANG"]
        .iter()
        .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()));
    let looks_utf8 = locale.as_deref().is_some_and(|l| {
        let l = l.to_ascii_lowercase();
        l.contains("utf-8") || l.contains("utf8")
    });
    if !looks_utf8 {
        let shown = locale.as_deref().unwrap_or("(unset)");
        crate::log::stderr(format_args!(
            "koh: warning: locale {shown} does not look UTF-8; non-ASCII output may be garbled. \
             Set e.g. LANG=en_US.UTF-8."
        ));
    }
}

/// With `$KOH_LOG` set, log to that file at debug level (the terminal is the session's). It must
/// be a private file of this user's (see [`crate::identity::open_private_log`]), as debug logs
/// can be sensitive; failing that, nothing is logged. An empty `$KOH_LOG` is off, silently.
fn log_to_koh_log() {
    let Some(path) = std::env::var_os("KOH_LOG").filter(|path| !path.is_empty()) else {
        return;
    };
    match crate::identity::open_private_log(path.as_ref()) {
        Ok(file) => crate::log::init(std::sync::Mutex::new(file), tracing::Level::DEBUG),
        Err(e) => {
            crate::log::stderr(format_args!(
                "koh: warning: $KOH_LOG: {e}; file logging disabled"
            ));
        }
    }
}

/// `koh connect`: the remote shell's exit code if it exited. Takes the process's terminal, stdin
/// and signal handlers for the session.
pub async fn connect(args: ConnectConfig) -> anyhow::Result<Option<u32>> {
    log_to_koh_log();
    warn_if_locale_not_utf8();
    // Before dialing, so a run with no terminal (a script's, an agent's) starts nothing there.
    let mut backend = DefaultBackend::new().map_err(|error| {
        anyhow::anyhow!(
            "`koh connect` needs a terminal, and there is none here ({error}); \
             `koh exec SERVER -- COMMAND` runs a command without one, `koh run` a job, and \
             `koh cp` copies files"
        )
    })?;
    // Held for the session: its lease stops `koh key reset` while it may redial.
    let identity = crate::identity::load(&crate::identity::KeyFile::locate(
        args.remote.key_file.clone(),
        "client",
    )?)?;
    let size = backend.size().unwrap_or(crate::terminal::DEFAULT_SIZE);
    let (endpoint, connector) = connector(&args.remote, &identity, Idle::Shell).await?;
    let admitted: Admitted = first_dial(&endpoint, connector.connect(args.pick, size)).await?;
    // For the menu's "last connected"; failing to note it never stops the session.
    let noted = crate::identity::KeyFile::path_for(args.remote.key_file.clone(), "client")
        .map_err(anyhow::Error::from)
        .and_then(|key| crate::names::record_connected(&key, args.remote.server));
    if let Err(error) = noted {
        tracing::debug!(error = %format!("{error:#}"), "noting when the server was reached");
    }
    let dialed_at = std::time::SystemTime::now();
    let shutdown = CancellationToken::new();
    // Armed before raw mode is entered, so an install error surfaces while the terminal is cooked.
    crate::cancel_on_signals(&shutdown).context("installing the signal handlers")?;
    let (channels, tasks) = super::spawn_client_io()?;
    backend.enter_raw_mode().context("entering raw mode")?;
    let run = super::Run {
        backend,
        size,
        colours: args.colours,
        clipboard: args.clipboard,
        links: args.hyperlinks,
        bell: args.bell_command.map(BellHook::new),
    };
    let result = crate::client::run_client(
        admitted,
        dialed_at,
        connector,
        run,
        (channels.input_rx, channels.resize_rx),
        shutdown,
    )
    .await;
    let _ = close_endpoint(&endpoint).await;
    drop(identity);
    super::io::first_error(result, tasks.shutdown().await)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bell_hook_fires_on_a_rise_and_rate_limits_a_burst() {
        // Counts [0,1,1,2,3] at times [0,0,10,20,1500] spawn at index 1 and 4 only — the
        // first rise fires, the rises inside the 1 s window coalesce, the one past it fires.
        let t0 = Instant::now();
        let at = |ms| t0 + Duration::from_millis(ms);
        let mut h = BellHook::new("true");
        let counts = [0u64, 1, 1, 2, 3];
        let times = [0u64, 0, 10, 20, 1500];
        let fired: Vec<bool> = counts
            .iter()
            .zip(times.iter())
            .map(|(&c, &t)| h.observe(c, at(t)))
            .collect();
        assert_eq!(fired, [false, true, false, false, true]);
        // No rise, no spawn — even long after the window.
        assert!(!h.observe(3, at(10_000)));
    }

    #[test]
    fn bell_hook_command_scrubs_parent_koh_vars_and_exports_its_own() {
        use std::ffi::OsString;
        let dir = crate::test_runtime::scratch("bell-env");
        let out = dir.join("env.txt");
        let hook = BellHook::new(format!("env > '{}'", out.display()));
        let parent_env = [
            ("KOH_DNS", "1.1.1.1"),
            ("KOH_LOG", "/x"),
            ("PATH", "/usr/bin:/bin"),
            ("HOME", "/nonexistent"),
        ]
        .into_iter()
        .map(|(k, v)| (OsString::from(k), OsString::from(v)));
        let status = hook
            .command(42, "a title", parent_env)
            .status()
            .expect("spawn env");
        let content = std::fs::read_to_string(&out).unwrap_or_default();
        assert!(status.success(), "{content}");
        assert!(content.contains("KOH_BELL_COUNT=42"), "{content}");
        assert!(content.contains("KOH_TITLE=a title"), "{content}");
        assert!(content.contains("PATH=/usr/bin:/bin"), "{content}");
        assert!(!content.contains("KOH_DNS"), "{content}");
        assert!(!content.contains("KOH_LOG"), "{content}");
    }

    #[test]
    fn sizes_read_as_a_person_reads_them() {
        assert_eq!(bytes(0), "0 B");
        assert_eq!(bytes(999), "999 B");
        assert_eq!(bytes(41_000), "41 KB");
        assert_eq!(bytes(1_234_567), "1.2 MB");
        assert_eq!(bytes(u64::MAX), "18446744073 GB");
    }
}
