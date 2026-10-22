//! What a connection is for: the opening request the client makes on its first stream, and the
//! server's answers to it.
//!
//! After the handshake the client opens a uni stream and writes on it its [`KeyProof`], then one
//! [`Request`]: each a 4-byte big-endian length then its postcard encoding. The server reads the
//! request only once the allowlist has the key proved, and attaches or starts nothing before it.
//! What the stream carries after the request is the request's: a shell's input
//! ([`crate::proto::ClientMsg`]), a command's stdin, or a copy's items ([`crate::sync`]). The
//! server answers on uni streams of its own: a shell's first one carries [`Attached`] (then what
//! the program shows follows, [`crate::proto`]), a command's a tag ([`ExecStream`]) then its output
//! or its [`ExitStatus`], the others an [`Answer`].
//!
//! Everything here is pure: each type refuses, as it is decoded, what is past its bound or names
//! nothing (a path holding a NUL byte, an empty command), so a value holds only what may be acted
//! on.

use serde::de::{self, DeserializeOwned, Deserializer};
use serde::{Deserialize, Serialize};

use crate::bounded::at_most;
use crate::proto::ProtoError;
use crate::terminal::{Activity, Size};

/// Most bytes of an opening request.
pub const MAX_REQUEST: usize = 1 << 20;

/// Most bytes of an answer sent whole ([`Attached`], a listing, a copy's outcome).
pub const MAX_REPLY: usize = 1 << 20;

/// Most bytes of a session's text `koh output` brings, and so of its answer.
pub const MAX_OUTPUT: usize = 8 << 20;

/// Most bytes of a path named on the other end: Linux's `PATH_MAX`.
pub const MAX_PATH: usize = 4096;

/// Most bytes of a [`KeyProof`]: a key and a signature, with room to spare.
pub const MAX_PROOF: usize = 128;

/// Most bytes of a command: its words together, or its shell line.
pub const MAX_COMMAND: usize = 256 * 1024;

/// Most words of a command.
pub const MAX_ARGS: usize = 4096;

/// Most sources one copy names.
pub const MAX_SOURCES: usize = 1024;

/// Most sessions or jobs a listing holds.
pub const MAX_LISTED: usize = 1024;

/// Most characters of a title, or of a job's command as listed.
pub const MAX_TITLE: usize = 256;

/// Most bytes of a job's name.
pub const MAX_JOB_NAME: usize = 64;

/// Most bytes of the text `koh wait --text` waits for.
pub const MAX_WAIT_TEXT: usize = 4096;

/// Most bytes of what a [`Problem`] says beside its kind.
pub const MAX_DETAIL: usize = 4096;

/// Most bytes of the log a [`LogMsg::Data`] brings.
pub const MAX_LOG_CHUNK: usize = 64 * 1024;

/// A session's number, server-wide: each new session takes the next, from 1, for the server's
/// run.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct SessionNum(pub u64);

impl std::fmt::Display for SessionNum {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// One run of a server, random: session numbers start again at 1 when a server restarts, so a
/// number alone could name another session after it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunId(pub u64);

impl RunId {
    /// A new one, from the OS's randomness.
    pub fn random() -> std::io::Result<Self> {
        let mut bytes = [0u8; 8];
        getrandom::fill(&mut bytes)?;
        Ok(Self(u64::from_le_bytes(bytes)))
    }
}

/// A session of one server run: what a client attached to, and redials to after a drop.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resume {
    pub run: RunId,
    pub session: SessionNum,
}

/// Which of the peer's sessions a shell attaches to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Pick {
    /// The one most recently attached, else a new one.
    Latest,
    /// Always a new one.
    New,
    /// That one, if it is the peer's, else [`Close::NoSuchSession`](crate::proto::Close).
    Id(SessionNum),
    /// That one of that run: the client's redial to the session it was on. A server run since
    /// restarted has no such session, whatever its numbers.
    Resume(Resume),
}

/// The client's key, proven: what a connection opens with, before its [`Request`].
///
/// A client dials from a key made for its process alone, so two of its processes at once never
/// share an endpoint id: iroh routes by that id, and two endpoints sharing one take each other's
/// paths (the relay keeps only the newest). The key the server allows is proven here instead, by
/// its signature over what this one connection's TLS session exports
/// ([`crate::transport_iroh::prove`]), which no other connection can reuse.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyProof {
    pub key: iroh::PublicKey,
    pub signature: iroh::Signature,
}

/// What the connection is for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    /// A detachable shell session, for a terminal of `size`: the stream goes on as the shell's
    /// input. With a `program`, a new session running it in place of the shell; with a `cwd`, a
    /// new session starting there (else in the server user's home).
    Shell {
        pick: Pick,
        size: Size,
        program: Option<Argv>,
        cwd: Option<RemotePath>,
    },
    /// The peer's sessions, answered as an [`Answer<SessionList>`].
    Sessions,
    /// A session's text: its screen, or the output of the last command its shell finished.
    Output { session: SessionNum, last: bool },
    /// Run a command with no terminal for as long as the connection lasts: the stream goes on as
    /// its stdin. Its stdout and stderr are one pipe if `together` (the client's are one file),
    /// so their order is the order it wrote them, all sent as its stdout.
    Exec { run: Run, together: bool },
    /// Start a job: a command with no terminal that outlives the connection, its output kept.
    Start { name: Option<JobName>, run: Run },
    /// The peer's jobs, answered as an [`Answer<JobList>`], their commands cut to
    /// [`MAX_TITLE`] characters; or the one `job` names, its command whole.
    Jobs { job: Option<JobName> },
    /// A job's output: what is kept (only its last `tail` lines, if given), then, if `follow`,
    /// what it writes until it ends.
    Logs {
        job: JobName,
        follow: bool,
        tail: Option<u32>,
    },
    /// Send a job's processes a signal.
    Kill { job: JobName, signal: Signal },
    /// Wait for something on the server.
    Wait(Wait),
    /// Copy files to or from the server.
    Copy(crate::sync::Copy),
}

impl Request {
    /// What the request does, for the server's log and a scoped key's refusal.
    pub const fn what(&self) -> &'static str {
        match self {
            Self::Shell { .. } => "a shell",
            Self::Sessions => "the session list",
            Self::Output { .. } => "a session's text",
            Self::Exec { .. } => "a command",
            Self::Start { .. } => "a job",
            Self::Jobs { .. } => "the job list",
            Self::Logs { .. } => "a job's output",
            Self::Kill { .. } => "a signal to a job",
            Self::Wait(_) => "a wait",
            Self::Copy(_) => "a copy",
        }
    }
}

/// A command and where it starts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Run {
    pub command: Command,
    /// The directory it starts in, as a [`RemotePath`]; `None` for the server user's home (or a
    /// scoped key's directory).
    pub cwd: Option<RemotePath>,
}

/// A command, as words run as they are, or a line for the server user's shell.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Command {
    /// The program and its arguments, each passed as it is: no shell splits or expands them. A
    /// program named `~/x` is in the server user's home.
    Argv(Argv),
    /// A line run by the server user's shell (`$SHELL -c`).
    Shell(CommandLine),
}

impl Command {
    /// The command as a person reads it: its words joined with spaces.
    pub fn display(&self) -> String {
        match self {
            Self::Argv(argv) => argv
                .words()
                .iter()
                .map(|word| String::from_utf8_lossy(word))
                .collect::<Vec<_>>()
                .join(" "),
            Self::Shell(line) => String::from_utf8_lossy(line.as_bytes()).into_owned(),
        }
    }
}

/// A command's words: at least one, the first not empty, at most [`MAX_ARGS`] of them holding at
/// most [`MAX_COMMAND`] bytes together, none holding a NUL, which no argument can.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Argv(Vec<Vec<u8>>);

impl Argv {
    pub fn new(words: Vec<Vec<u8>>) -> Result<Self, &'static str> {
        match words.first() {
            None => return Err("an empty command"),
            Some(first) if first.is_empty() => return Err("an empty program name"),
            Some(_) => {}
        }
        if words.len() > MAX_ARGS {
            return Err("a command of more than 4096 words");
        }
        let bytes = words.iter().fold(0_usize, |n, w| n.saturating_add(w.len()));
        if bytes > MAX_COMMAND {
            return Err("a command over 256 KiB");
        }
        if words.iter().any(|w| w.contains(&0)) {
            return Err("a command holding a NUL byte");
        }
        Ok(Self(words))
    }

    pub fn words(&self) -> &[Vec<u8>] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Argv {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Word(#[serde(deserialize_with = "at_most::<MAX_COMMAND, _, _>")] Vec<u8>);
        let words = at_most::<MAX_ARGS, D, Word>(deserializer)?;
        Self::new(words.into_iter().map(|Word(w)| w).collect()).map_err(de::Error::custom)
    }
}

/// A line for the server user's shell: at least a byte, at most [`MAX_COMMAND`], no NUL.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CommandLine(Vec<u8>);

impl CommandLine {
    pub fn new(bytes: Vec<u8>) -> Result<Self, &'static str> {
        if bytes.is_empty() {
            return Err("an empty command");
        }
        if bytes.len() > MAX_COMMAND {
            return Err("a command over 256 KiB");
        }
        if bytes.contains(&0) {
            return Err("a command holding a NUL byte");
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for CommandLine {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = at_most::<MAX_COMMAND, D, u8>(deserializer)?;
        Self::new(bytes).map_err(de::Error::custom)
    }
}

/// A job's name: 1 to [`MAX_JOB_NAME`] letters, digits, `.`, `_` and `-`, not starting with `-`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct JobName(String);

impl JobName {
    pub fn new(name: &str) -> Result<Self, &'static str> {
        let fits = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-');
        if name.is_empty() || name.len() > MAX_JOB_NAME || name.starts_with('-') {
            return Err("a job name is 1 to 64 letters, digits, `.`, `_` or `-`, not first `-`");
        }
        if !name.bytes().all(fits) {
            return Err("a job name is 1 to 64 letters, digits, `.`, `_` or `-`, not first `-`");
        }
        Ok(Self(name.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for JobName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for JobName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = at_most::<MAX_JOB_NAME, D, u8>(deserializer)?;
        let name = String::from_utf8(bytes).map_err(de::Error::custom)?;
        Self::new(&name).map_err(de::Error::custom)
    }
}

/// A signal `koh kill` sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Signal {
    Term,
    Kill,
    Int,
    Hup,
}

impl Signal {
    pub fn named(name: &str) -> Option<Self> {
        let name = name.strip_prefix("SIG").unwrap_or(name);
        Some(match name.to_ascii_uppercase().as_str() {
            "TERM" | "15" => Self::Term,
            "KILL" | "9" => Self::Kill,
            "INT" | "2" => Self::Int,
            "HUP" | "1" => Self::Hup,
            _ => return None,
        })
    }
}

/// What `koh wait` waits on, and for what.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Wait {
    pub on: Option<On>,
    pub until: Until,
}

impl Wait {
    /// A wait, if it names something to wait for: a file needs nothing to be on, the end and text
    /// a job or a session, and reading a session.
    pub fn new(on: Option<On>, until: Until) -> Result<Self, &'static str> {
        match (&on, &until) {
            (_, Until::File(_))
            | (Some(_), Until::End | Until::Text(_))
            | (Some(On::Session(_)), Until::Reading) => {}
            (Some(On::Job(_)), Until::Reading) => return Err("only a session waits for reading"),
            (None, _) => return Err("a wait for a job or a session's end or text names it"),
        }
        Ok(Self { on, until })
    }
}

impl<'de> Deserialize<'de> for Wait {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            on: Option<On>,
            until: Until,
        }
        let Raw { on, until } = Raw::deserialize(deserializer)?;
        Self::new(on, until).map_err(de::Error::custom)
    }
}

/// What a wait is on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum On {
    Job(JobName),
    /// The command running in a session's shell, or its program.
    Session(SessionNum),
}

/// What a wait is for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Until {
    /// A job's end, or the end of the command running in a session (at once if none runs).
    End,
    /// This text in a job's output, or on a session's screen.
    Text(WaitText),
    /// This path to exist on the server.
    File(RemotePath),
    /// A session's program to be reading its terminal: at a prompt, a REPL, a pager.
    Reading,
}

/// Text to wait for: 1 to [`MAX_WAIT_TEXT`] bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WaitText(String);

impl WaitText {
    pub fn new(text: String) -> Result<Self, &'static str> {
        if text.is_empty() || text.len() > MAX_WAIT_TEXT {
            return Err("text to wait for is 1 to 4096 bytes");
        }
        Ok(Self(text))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for WaitText {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = at_most::<MAX_WAIT_TEXT, D, u8>(deserializer)?;
        let text = String::from_utf8(bytes).map_err(de::Error::custom)?;
        Self::new(text).map_err(de::Error::custom)
    }
}

/// A path on the server as the client wrote it: at most [`MAX_PATH`] bytes, no NUL.
///
/// Empty, `~` and `~/…` are the server user's home and what is in it, and a relative path is
/// relative to it, as that user's shell would take them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RemotePath(Vec<u8>);

impl RemotePath {
    /// `bytes`, if a path may hold them.
    pub fn new(bytes: Vec<u8>) -> Result<Self, &'static str> {
        if bytes.len() > MAX_PATH {
            return Err("a path over 4096 bytes");
        }
        if bytes.contains(&0) {
            return Err("a path holding a NUL byte");
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for RemotePath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = at_most::<MAX_PATH, D, u8>(deserializer)?;
        Self::new(bytes).map_err(de::Error::custom)
    }
}

/// The sources of a copy from the server: at least one, at most [`MAX_SOURCES`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Sources(Vec<RemotePath>);

impl Sources {
    pub fn new(paths: Vec<RemotePath>) -> Result<Self, &'static str> {
        match paths.len() {
            0 => Err("no sources"),
            n if n > MAX_SOURCES => Err("more than 1024 sources"),
            _ => Ok(Self(paths)),
        }
    }

    pub fn paths(&self) -> &[RemotePath] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Sources {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let paths = at_most::<MAX_SOURCES, D, RemotePath>(deserializer)?;
        Self::new(paths).map_err(de::Error::custom)
    }
}

/// A shell's admission, on the server's first stream: the session it attached, which the client
/// redials to after a drop.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attached {
    pub at: Resume,
}

/// Why the server could not do what was asked: a kind, which says it the same whatever systems
/// the ends run, and what the server adds (a path, a name), shown escaped.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[error("{}", self.text())]
pub struct Problem {
    pub kind: ProblemKind,
    #[serde(deserialize_with = "detail")]
    pub detail: String,
}

fn detail<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    let bytes = at_most::<MAX_DETAIL, D, u8>(deserializer)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

impl Problem {
    pub fn new(kind: ProblemKind, detail: impl std::fmt::Display) -> Self {
        let mut detail = detail.to_string();
        if detail.len() > MAX_DETAIL {
            let mut end = MAX_DETAIL;
            while !detail.is_char_boundary(end) {
                end = end.saturating_sub(1);
            }
            detail.truncate(end);
        }
        Self { kind, detail }
    }

    /// What it says, for a person: the detail, escaped, then the kind's words.
    pub fn text(&self) -> String {
        let said = self.kind.text();
        if self.detail.is_empty() {
            said.to_owned()
        } else {
            format!("{}: {said}", crate::log::Peer(&self.detail))
        }
    }
}

/// What went wrong, by kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProblemKind {
    /// No job of the peer's has that name.
    NoSuchJob,
    /// No session of the peer's has that number.
    NoSuchSession,
    /// A job of that name is still running.
    NameTaken,
    /// The server holds as many jobs as it keeps.
    TooManyJobs,
    /// The command could not start (no such program, say).
    CouldNotStart,
    /// The key may not do this, or not there.
    OutOfScope,
    /// The server user has no home directory, which the path is relative to.
    NoHome,
    /// The path is not there.
    NotFound,
    /// Anything else.
    Failed,
    /// The directory a command was to start in is not there, or is not a directory.
    NoSuchDir,
    /// The program to run is not there (its directory to start in was).
    NoSuchProgram,
}

impl ProblemKind {
    /// The status a command that did not start for this exits with, as a shell's: 127 no such
    /// program, 126 it could not start (no such directory to start in, say).
    pub const fn not_started_status(self) -> Option<u8> {
        match self {
            Self::NoSuchProgram => Some(127),
            Self::NoSuchDir | Self::CouldNotStart => Some(126),
            Self::NoSuchJob
            | Self::NoSuchSession
            | Self::NameTaken
            | Self::TooManyJobs
            | Self::OutOfScope
            | Self::NoHome
            | Self::NotFound
            | Self::Failed => None,
        }
    }

    /// Its name in `--json` output.
    pub const fn name(self) -> &'static str {
        match self {
            Self::NoSuchJob => "no_such_job",
            Self::NoSuchSession => "no_such_session",
            Self::NameTaken => "name_taken",
            Self::TooManyJobs => "too_many_jobs",
            Self::CouldNotStart => "could_not_start",
            Self::OutOfScope => "out_of_scope",
            Self::NoHome => "no_home",
            Self::NotFound => "not_found",
            Self::Failed => "failed",
            Self::NoSuchDir => "no_such_dir",
            Self::NoSuchProgram => "no_such_program",
        }
    }

    pub const fn text(self) -> &'static str {
        match self {
            Self::NoSuchJob => "no such job (`koh jobs` lists them)",
            Self::NoSuchSession => "no such session (`koh sessions` lists them)",
            Self::NameTaken => "a job of that name is still running",
            Self::TooManyJobs => "the server keeps no more jobs (wait for one, or reuse a name)",
            Self::CouldNotStart => "could not start",
            Self::OutOfScope => "this key may not do that",
            Self::NoHome => "the server user has no home directory",
            Self::NotFound => "no such file or directory",
            Self::Failed => "failed",
            Self::NoSuchDir => {
                "no such directory on the server to start in (-C takes the server's path; a \
                 relative one is in its home)"
            }
            Self::NoSuchProgram => "no such program",
        }
    }
}

/// An answer: what was asked, or why not.
pub type Answer<T> = Result<T, Problem>;

/// Whether a client is attached to a session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Presence {
    Attached,
    /// No client for these seconds.
    Detached {
        secs: u64,
    },
}

/// What a session's shell is doing, as its marks say, and what its program does, as probed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellState {
    /// What the program in the foreground is doing; `None` before it was probed.
    pub activity: Option<Activity>,
    /// A command the shell started has not ended.
    pub running: bool,
    /// How many commands ended.
    pub finished: u64,
    /// The status the last one ended with, if its shell said.
    pub last_status: Option<i32>,
}

/// One of the peer's sessions, as listed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionInfo {
    pub session: SessionNum,
    /// Seconds since it started.
    pub age_secs: u64,
    pub presence: Presence,
    pub size: Size,
    /// Its window title, at most [`MAX_TITLE`] characters.
    #[serde(deserialize_with = "title")]
    pub title: String,
    /// Its program's exit status, once it exited: the session is kept until a client sees it.
    pub exited: Option<u32>,
    pub state: ShellState,
}

fn title<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    let bytes = at_most::<{ MAX_TITLE * 4 }, D, u8>(deserializer)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn command<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    let bytes = at_most::<MAX_COMMAND, D, u8>(deserializer)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// The peer's sessions, oldest first.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionList(
    #[serde(deserialize_with = "at_most::<MAX_LISTED, _, _>")] pub Vec<SessionInfo>,
);

/// A job started: its name, given or the next number.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Started {
    pub name: JobName,
}

/// How a job stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobState {
    Running,
    /// Its status: its exit code, or 128 plus the signal that killed it.
    Exited(u32),
}

/// One of the peer's jobs, as listed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobInfo {
    pub name: JobName,
    /// Its command, as a person reads it: at most [`MAX_TITLE`] characters in a listing, at most
    /// [`MAX_COMMAND`] bytes asked for by name.
    #[serde(deserialize_with = "command")]
    pub command: String,
    /// Seconds since it started.
    pub age_secs: u64,
    /// Seconds it ran, once it ended.
    pub ran_secs: Option<u64>,
    pub state: JobState,
    /// Bytes it wrote, the dropped ones included.
    pub output_bytes: u64,
    /// Of those, how many are no longer kept: the oldest go once the log is full.
    pub dropped_bytes: u64,
    /// While it runs, what its session's processes use, where the server's system says: a job
    /// that writes to a file of its own shows no output, but this shows it at work.
    pub usage: Option<Usage>,
}

/// What a running job's processes (those in the session it leads) use.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    /// How many there are.
    pub processes: u32,
    /// The CPU time they used, and their children that ended used, in milliseconds.
    pub cpu_ms: u64,
}

/// The peer's jobs, oldest first.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobList(#[serde(deserialize_with = "at_most::<MAX_LISTED, _, _>")] pub Vec<JobInfo>);

/// What a wait ended on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Waited {
    /// The job, or the session's command, ended: its status, if known.
    Ended(Option<i64>),
    /// The text appeared.
    Text,
    /// The file appeared.
    File,
    /// The session's program is reading its terminal.
    Reading,
}

/// One message of a job's output, as `koh logs` reads it, framed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogMsg {
    /// The output that went before was dropped, this many bytes, as the log was full.
    Dropped(u64),
    /// This many lines of what is kept went before what is sent, left out as `tail` asked.
    Cut(u64),
    /// Output, as the job wrote it.
    Data(#[serde(deserialize_with = "at_most::<MAX_LOG_CHUNK, _, _>")] Vec<u8>),
    /// The end of what is sent: the job's status if it ended, `None` if it runs on (no follow),
    /// and the seconds it ran, or has run so far.
    End { exit: Option<u32>, secs: u64 },
    /// Why there is no log to send (no such job), in place of the rest.
    Problem(Problem),
}

/// What a stream the server opens for `koh exec` carries, its first byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ExecStream {
    /// The command's stdout, to its end.
    Stdout = 0,
    /// Its stderr, to its end.
    Stderr = 1,
    /// Its [`ExitStatus`], once both have ended.
    Status = 2,
}

impl ExecStream {
    pub const fn tag(self) -> u8 {
        self as u8
    }

    pub const fn from_tag(tag: u8) -> Option<Self> {
        Some(match tag {
            0 => Self::Stdout,
            1 => Self::Stderr,
            2 => Self::Status,
            _ => return None,
        })
    }
}

/// How a command ended, as a shell reports it: its exit code, or 128 plus the signal that killed
/// it; or why it never started.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExitStatus {
    Exited(u32),
    NotStarted(Problem),
}

/// `msg` with its 4-byte big-endian length before it, refused past `max` bytes.
pub fn encode<T: Serialize>(msg: &T, max: usize) -> Result<Vec<u8>, ProtoError> {
    let mut out = postcard::to_extend(msg, vec![0; 4])?;
    let body = out.len().saturating_sub(4);
    if body > max {
        return Err(ProtoError::TooLarge { len: body, max });
    }
    if let Some(prefix) = out.first_chunk_mut::<4>() {
        *prefix = u32::try_from(body).unwrap_or(u32::MAX).to_be_bytes();
    }
    Ok(out)
}

/// The length a 4-byte big-endian prefix announces, refused past `max`.
pub fn body_len(prefix: [u8; 4], max: usize) -> Result<usize, ProtoError> {
    let len = usize::try_from(u32::from_be_bytes(prefix)).unwrap_or(usize::MAX);
    if len > max {
        return Err(ProtoError::TooLarge { len, max });
    }
    Ok(len)
}

/// Decode a message's body (its length prefix read already), all of it.
pub fn decode<T: DeserializeOwned>(body: &[u8]) -> Result<T, ProtoError> {
    Ok(postcard::from_bytes(body)?)
}

/// Decode a whole framed message, prefix and body, as a reply stream carries it.
pub fn decode_framed<T: DeserializeOwned>(bytes: &[u8], max: usize) -> Result<T, ProtoError> {
    let (prefix, body) = bytes
        .split_first_chunk::<4>()
        .ok_or(ProtoError::Truncated)?;
    if body_len(*prefix, max)? != body.len() {
        return Err(ProtoError::Truncated);
    }
    decode(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(request: &Request) -> Request {
        let bytes = encode(request, MAX_REQUEST).unwrap();
        decode_framed(&bytes, MAX_REQUEST).unwrap()
    }

    #[test]
    fn requests_round_trip_and_what_names_nothing_is_refused_as_it_is_decoded() {
        // Built by hand past the constructors: refused on the way in.
        #[derive(Serialize)]
        enum Raw {
            #[expect(dead_code, reason = "a variant's place, as Request numbers them")]
            Shell,
            #[expect(dead_code, reason = "a variant's place, as Request numbers them")]
            Sessions,
            #[expect(dead_code, reason = "a variant's place, as Request numbers them")]
            Output,
            Exec(RawRun, bool),
            Start(Option<String>, RawRun),
            #[expect(dead_code, reason = "a variant's place, as Request numbers them")]
            Jobs,
            #[expect(dead_code, reason = "a variant's place, as Request numbers them")]
            Logs,
            #[expect(dead_code, reason = "a variant's place, as Request numbers them")]
            Kill,
            Wait(Option<RawOn>, RawUntil),
        }
        #[derive(Serialize)]
        struct RawRun(RawCommand, Option<Vec<u8>>);
        #[derive(Serialize)]
        enum RawCommand {
            Argv(Vec<Vec<u8>>),
            Shell(Vec<u8>),
        }
        #[derive(Serialize)]
        enum RawOn {
            Job(String),
        }
        #[derive(Serialize)]
        enum RawUntil {
            End,
            Text(String),
            #[expect(dead_code, reason = "a variant's place, as Until numbers them")]
            File,
            Reading,
        }
        let path = |p: &[u8]| RemotePath::new(p.to_vec()).unwrap();
        let argv = |words: &[&str]| {
            Command::Argv(Argv::new(words.iter().map(|w| w.as_bytes().to_vec()).collect()).unwrap())
        };
        for request in [
            Request::Shell {
                pick: Pick::Resume(Resume {
                    run: RunId(7),
                    session: SessionNum(3),
                }),
                size: Size::new(24, 80),
                program: None,
                cwd: None,
            },
            Request::Shell {
                pick: Pick::New,
                size: Size::new(24, 80),
                program: Some(Argv::new(vec![b"gdb".to_vec(), b"./a.out".to_vec()]).unwrap()),
                cwd: Some(path(b"proj")),
            },
            Request::Exec {
                run: Run {
                    command: argv(&["echo", "a b"]),
                    cwd: Some(path(b"src")),
                },
                together: true,
            },
            Request::Start {
                name: Some(JobName::new("build").unwrap()),
                run: Run {
                    command: Command::Shell(CommandLine::new(b"make -j4".to_vec()).unwrap()),
                    cwd: None,
                },
            },
            Request::Wait(
                Wait::new(
                    Some(On::Job(JobName::new("build").unwrap())),
                    Until::Text(WaitText::new("listening".into()).unwrap()),
                )
                .unwrap(),
            ),
            Request::Wait(Wait::new(None, Until::File(path(b"~/done"))).unwrap()),
        ] {
            assert_eq!(round_trip(&request), request);
        }
        let run = |command| RawRun(command, None);
        for raw in [
            Raw::Exec(run(RawCommand::Argv(Vec::new())), false),
            Raw::Exec(run(RawCommand::Argv(vec![Vec::new()])), false),
            Raw::Exec(run(RawCommand::Argv(vec![b"a\0b".to_vec()])), false),
            Raw::Exec(
                run(RawCommand::Argv(vec![b"x".to_vec(); MAX_ARGS + 1])),
                false,
            ),
            Raw::Exec(run(RawCommand::Shell(Vec::new())), false),
            Raw::Exec(run(RawCommand::Shell(vec![b'x'; MAX_COMMAND + 1])), false),
            Raw::Exec(
                RawRun(RawCommand::Shell(b"x".to_vec()), Some(b"a\0".to_vec())),
                false,
            ),
            Raw::Start(Some("-rf".into()), run(RawCommand::Shell(b"x".to_vec()))),
            Raw::Start(Some("a b".into()), run(RawCommand::Shell(b"x".to_vec()))),
            Raw::Wait(None, RawUntil::End),
            Raw::Wait(Some(RawOn::Job("b".into())), RawUntil::Reading),
            Raw::Wait(Some(RawOn::Job("b".into())), RawUntil::Text(String::new())),
        ] {
            let bytes = encode(&raw, usize::MAX).unwrap();
            assert!(decode_framed::<Request>(&bytes, usize::MAX).is_err());
        }
        // A prefix announcing more than the bound is refused before the body is read.
        assert!(body_len(u32::MAX.to_be_bytes(), MAX_REQUEST).is_err());
    }
}
