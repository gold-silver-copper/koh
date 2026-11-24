//! Wire protocol for koh/19 over iroh QUIC bidirectional streams.
//! Every message is length-prefixed (`u32` big-endian) postcard with strict byte bounds.

use iroh::endpoint::{RecvStream, SendStream};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::{Exit, KohError, Result};

/// ALPN for koh v2 (fux-backed) protocol.
pub const ALPN: &[u8] = b"koh/19";

pub const MAX_PROOF: usize = 512;
pub const MAX_CTRL: usize = 1 << 20; // 1 MiB
pub const MAX_FRAME: usize = 8 << 20; // 8 MiB
pub const MAX_CHUNK: usize = 256 << 10; // 256 KiB
/// The most bytes a session's client sends in one message: typed bytes, a line, what its terminal is like.
pub const MAX_TYPED: usize = 16 << 10;
/// The most typed bytes that wait at either end of a session: for a FIFO to take them on the
/// server, for a link on a client. With that many waiting no more are read, so a writer waits.
pub const MAX_HELD: usize = 64 << 10;

/// TLS-bound client authentication proof sent first on every connection's first stream.
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyProof {
    pub key: [u8; 32],
    pub signature: Vec<u8>,
}

/// Application-level QUIC close codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum CloseCode {
    Done = 0,
    Refused = 1,
    Busy = 2,
    Protocol = 3,
}

impl CloseCode {
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0 => Some(Self::Done),
            1 => Some(Self::Refused),
            2 => Some(Self::Busy),
            3 => Some(Self::Protocol),
            _ => None,
        }
    }
}

/// Top-level RPC request sent at the start of a QUIC bidirectional stream.
#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    Exec {
        argv: Vec<String>,
        cwd: Option<String>,
        shell: bool,
    },
    Run {
        name: Option<String>,
        argv: Vec<String>,
        cwd: Option<String>,
        shell: bool,
    },
    Jobs {
        name: Option<String>,
    },
    Logs {
        name: String,
        tail: Option<usize>,
        all: bool,
        follow: bool,
    },
    Kill {
        name: String,
        signal: i32,
    },
    WaitJob {
        name: String,
        text: Option<String>,
        tail: usize,
        timeout_secs: Option<u64>,
    },
    CpPush {
        dst: String,
        excludes: Vec<String>,
        delete: bool,
        preserve_mtime: bool,
        dry_run: bool,
    },
    CpPull {
        src: String,
        excludes: Vec<String>,
        delete: bool,
        preserve_mtime: bool,
        dry_run: bool,
        preserve_root: bool,
    },
    Attach(Attach),
    /// The three that read a session's folder on the server (`pane`), after `Attach`, whose
    /// number they leave as it was. `Sessions` is answered with a list of `SessionInfo`, in
    /// pieces as a text is: it is as long as the sessions that are kept make it.
    Sessions,
    /// A session's screen, or with `last` what its last command printed: `Ok`, then the text
    /// in pieces of bytes until the stream's end.
    Output {
        session: String,
        last: bool,
    },
    /// Until one more command of the session's shell has ended, the session has, or so many
    /// seconds have gone by: `Ok` once the request is taken, a `WaitResult` without its
    /// `tail` when it is over, then the tail as `Output`'s text.
    WaitSession {
        session: String,
        timeout_secs: Option<u64>,
    },
}

/// A session as its folder says it is, for `koh sessions`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub name: String,
    /// A client has a stream of it.
    pub attached: bool,
    /// What `state` says became of the program; `running` only while a holder lives, and
    /// `ended` where none does and nothing says how it ended.
    pub state: String,
    pub cols: usize,
    pub rows: usize,
    pub title: String,
    /// The shell's last mark is `output`.
    pub running_command: bool,
    /// The code of the last `end` mark, if the shell gave one.
    pub last_exit: Option<u8>,
    /// Since `status` was written, which is when the session started.
    pub age_secs: u64,
    pub pane_dir: String,
}

/// Asks for a stream of a session, which is a fux pane on the server: answered `Ok`, then
/// `Attached`, then the pane's folder in rounds (`ToMirror`) against what is typed (`FromMirror`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attach {
    /// The asker's `fux::FORMAT`: another than the server's is refused before anything is made.
    pub format: u32,
    /// The session. One that is not there is started under the name; with no name it is the
    /// newest that lives, or a new one (always, with `new` or a program).
    pub name: Option<String>,
    pub new: bool,
    pub cols: u16,
    pub rows: u16,
    pub argv: Vec<String>,
    pub cwd: Option<String>,
    /// The run this client mirrors, on every attach but its first: the session's folder is
    /// that run or the attach is refused, and nothing is started.
    pub run: Option<Run>,
    /// A number the client chose when it started: its older stream on the run is ended first.
    pub client: u64,
}

/// Which run of a session's name a folder is: the folder (its device and its number there) and
/// its holder's process number, which the first line of the pane's `status` has from the run's
/// start to its end. A name started anew is another run, also where it is given the old folder's number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Run {
    pub device: u64,
    pub folder: u64,
    pub holder: u64,
}

/// A name a session may have: one of fux's names (letters, digits, `.`, `_` and `-`, at most 64,
/// no dot first, none that fux keeps), and so one folder: never a path. Each end holds the
/// other's word to it.
pub fn session_name(name: &str) -> bool {
    let letters = |b: u8| b.is_ascii_alphanumeric() || b"._-".contains(&b);
    // (And none of the four names fux keeps for itself in a session and a workspace.)
    let kept = ["-", "colours", "keyboard", "layout"].contains(&name);
    let fits = !name.is_empty() && name.len() <= 64 && !name.starts_with('.');
    fits && !kept && name.bytes().all(letters)
}

/// What follows `Ok` on an attach: the session's name and its run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attached {
    pub name: String,
    pub run: Run,
}

/// Initial server status reply to any `Request`.
#[derive(Debug, Serialize, Deserialize)]
pub enum Reply {
    Ok,
    Err {
        code: u8,
        kind: String,
        message: String,
    },
}

impl Reply {
    pub fn from_err(err: &KohError) -> Self {
        Self::Err {
            code: err.code.0,
            kind: err.kind.to_string(),
            message: err.message.clone(),
        }
    }

    pub fn into_result(self) -> Result<()> {
        match self {
            Self::Ok => Ok(()),
            Self::Err {
                code,
                kind,
                message,
            } => Err(KohError::new(exit_of(code), kind_of(&kind), message)),
        }
    }
}

/// Streaming messages during `Exec`.
#[derive(Debug, Serialize, Deserialize)]
pub enum ExecServerMsg {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Exit(i32),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ExecClientMsg {
    Stdin(Vec<u8>),
    Eof,
}

/// Job summary returned by `Run` / `Jobs`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobInfo {
    pub name: String,
    pub pid: u32,
    pub state: String,
    pub exit: Option<i32>,
    pub age_secs: u64,
    pub command: String,
}

/// Streaming log message for `Logs`.
#[derive(Debug, Serialize, Deserialize)]
pub enum LogMsg {
    Data(Vec<u8>),
    Done {
        state: String,
        exit: Option<i32>,
        age_secs: u64,
    },
}

/// Result of `WaitJob` and of `WaitSession`.
#[derive(Debug, Serialize, Deserialize)]
pub struct WaitResult {
    pub timed_out: bool,
    pub exit: i32,
    pub tail: String,
    pub detail: String,
}

/// Delta sync file entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncEntry {
    pub path: String,
    pub size: u64,
    pub mtime_secs: i64,
    pub mode: u32,
    pub hash: [u8; 32],
    pub is_dir: bool,
}

/// Delta sync wire messages.
#[derive(Debug, Serialize, Deserialize)]
pub enum SyncMsg {
    Manifest(Vec<SyncEntry>),
    Need(Vec<String>),
    FileStart {
        path: String,
        size: u64,
        mtime_secs: i64,
        mode: u32,
    },
    FileChunk(Vec<u8>),
    FileEnd,
    Summary(SyncSummary),
    /// The end that could not go on says why.
    Failed(Failure),
}

/// Why an end of a copy stopped, as its own caller would be told: the exit code, kind and words.
#[derive(Debug, Serialize, Deserialize)]
pub struct Failure {
    pub code: u8,
    pub kind: String,
    pub message: String,
}

impl From<&KohError> for Failure {
    fn from(err: &KohError) -> Self {
        Self {
            code: err.code.0,
            kind: err.kind.to_string(),
            // (A message quotes paths a peer sent: it stays well inside a control message.)
            message: err.message.chars().take(4096).collect(),
        }
    }
}

impl From<Failure> for KohError {
    fn from(said: Failure) -> Self {
        Self::new(exit_of(said.code), kind_of(&said.kind), said.message)
    }
}

/// The exit code a peer gave for what went wrong, as one of koh's own for a failure: a peer cannot
/// make a failure exit 0, or with a code koh does not have.
fn exit_of(code: u8) -> Exit {
    let known = [
        Exit::USAGE,
        Exit::UNREACHABLE,
        Exit::REFUSED,
        Exit::BUSY,
        Exit::TIMEOUT,
        Exit::CANNOT_START,
        Exit::NOT_FOUND,
        Exit::INTERNAL,
    ];
    if known.contains(&Exit(code)) {
        Exit(code)
    } else {
        Exit::FAILED
    }
}

/// A kind a peer named, as one of ours: an error's kind is a fixed word.
fn kind_of(kind: &str) -> &'static str {
    match kind {
        "refused" => "refused",
        "usage" => "usage",
        "unreachable" => "unreachable",
        "timeout" => "timeout",
        "busy" => "busy",
        "not_found" => "not_found",
        "cannot_start" => "cannot_start",
        "failed" => "failed",
        _ => "remote",
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyncSummary {
    pub added: Vec<String>,
    pub updated: Vec<String>,
    pub deleted: Vec<String>,
    pub unchanged: usize,
    pub bytes_transferred: u64,
    pub dry_run: bool,
}

impl SyncSummary {
    pub fn merge(&mut self, other: Self) {
        self.added.extend(other.added);
        self.updated.extend(other.updated);
        self.deleted.extend(other.deleted);
        self.unchanged += other.unchanged;
        self.bytes_transferred += other.bytes_transferred;
        self.dry_run |= other.dry_run;
    }
}

/// What a name in a pane's folder is the name of. Nothing else is carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Kind {
    File,
    Folder,
    Link,
    Fifo,
}

/// One thing a client's mirror has: its name, its kind, and of a file its length and its hash
/// (blake3). A server believes none of it that its own bytes do not bear out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Had {
    pub name: String,
    pub kind: Kind,
    pub len: u64,
    pub hash: [u8; 32],
}

/// A stretch of a file that is told as lines of the file before it: `count` of that file's lines
/// from its line `from` (a line is bytes up to and with its `\n`), or bytes it has not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Edit {
    Run { from: u32, count: u32 },
    New(Vec<u8>),
}

/// What a server sends of a pane's folder. Everything from `Round` to `Done` is one round: a
/// client's mirror takes it whole or not at all (`carry`, which has each message's rule).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ToMirror {
    /// A round begins: the number `generation` has once it is applied.
    Round(u64),
    Folder(String),
    Fifo(String),
    Link {
        name: String,
        to: String,
    },
    /// A file, whole: in pieces that follow each other while `more`.
    Put {
        name: String,
        more: bool,
        bytes: Vec<u8>,
    },
    /// A file as lines of the one the mirror has under that name.
    Lines {
        name: String,
        edits: Vec<Edit>,
    },
    /// A file keeps its first `at` bytes and these follow; further pieces carry the place of
    /// their own first byte.
    Add {
        name: String,
        at: u64,
        bytes: Vec<u8>,
    },
    /// The file `from` is `to`.
    Moved {
        from: String,
        to: String,
    },
    /// It is gone: a folder with what is in it.
    Remove(String),
    /// The round is whole: now it is applied.
    Done,
    /// No holder is left: nothing follows.
    Ended,
}

/// What a client sends of its mirror: once, first, what the mirror has; then what was written to
/// the mirror's `in` and `ctl`, and what its viewer wrote of its terminal (`colours`, `keyboard`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FromMirror {
    Has(Vec<Had>),
    Write { name: String, bytes: Vec<u8> },
    Told { name: String, bytes: Vec<u8> },
}

/// A message as it is sent, without its length: refused when it is longer than `max`.
pub fn encode<T: Serialize>(value: &T, max: usize) -> Result<Vec<u8>> {
    let bytes =
        postcard::to_allocvec(value).map_err(|e| KohError::internal(format!("encode: {e}")))?;
    if bytes.len() > max {
        return Err(KohError::internal(format!(
            "message exceeds bound ({} > {max})",
            bytes.len()
        )));
    }
    Ok(bytes)
}

/// The message `bytes` are, and are all of: nothing may follow it, and it is no longer than `max`.
pub fn decode<T: DeserializeOwned>(bytes: &[u8], max: usize) -> Result<T> {
    if bytes.len() > max {
        return Err(KohError::failed(format!(
            "incoming message exceeds bound ({} > {max})",
            bytes.len()
        )));
    }
    match postcard::take_from_bytes(bytes) {
        Ok((value, [])) => Ok(value),
        Ok(_) => Err(KohError::failed("more in a message than it is")),
        Err(e) => Err(KohError::failed(format!("decode message: {e}"))),
    }
}

/// Encode and write one length-prefixed postcard frame.
pub async fn send_msg<T: Serialize>(stream: &mut SendStream, value: &T, max: usize) -> Result<()> {
    let bytes = encode(value, max)?;
    let len = u32::try_from(bytes.len()).map_err(|_| KohError::internal("message too large"))?;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|e| KohError::unreachable(format!("write length: {e}")))?;
    stream
        .write_all(&bytes)
        .await
        .map_err(|e| KohError::unreachable(format!("write body: {e}")))?;
    Ok(())
}

/// Read and decode one length-prefixed postcard frame, returning `Ok(None)` on clean EOF.
pub async fn recv_msg_opt<T: DeserializeOwned>(
    stream: &mut RecvStream,
    max: usize,
) -> Result<Option<T>> {
    let mut prefix = [0u8; 4];
    let mut read = 0usize;
    while read < 4 {
        let Some(slice) = prefix.get_mut(read..) else {
            break;
        };
        match stream.read(slice).await {
            Ok(Some(0)) | Ok(None) => {
                if read == 0 {
                    return Ok(None);
                }
                return Err(KohError::unreachable("unexpected EOF reading frame length"));
            }
            Ok(Some(n)) => read += n,
            Err(e) => return Err(KohError::unreachable(format!("read length: {e}"))),
        }
    }
    let len = u32::from_be_bytes(prefix) as usize;
    if len > max {
        return Err(KohError::failed(format!(
            "incoming message exceeds bound ({len} > {max})"
        )));
    }
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| KohError::unreachable(format!("read body: {e}")))?;
    decode(&buf, max).map(Some)
}

/// Sends bytes in pieces, a message each: a session's text, or a list of sessions, has no
/// bound of its own, and no message is over its bound.
pub async fn send_pieces(stream: &mut SendStream, bytes: &[u8]) -> Result<()> {
    for piece in bytes.chunks(64 << 10) {
        send_msg(stream, &piece, MAX_CHUNK).await?;
    }
    Ok(())
}

/// Reads what was sent in pieces, to the stream's end.
pub async fn recv_pieces(stream: &mut RecvStream) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    while let Some(mut piece) = recv_msg_opt::<Vec<u8>>(stream, MAX_CHUNK).await? {
        bytes.append(&mut piece);
    }
    Ok(bytes)
}

/// Read and decode one required frame.
pub async fn recv_msg<T: DeserializeOwned>(stream: &mut RecvStream, max: usize) -> Result<T> {
    recv_msg_opt(stream, max)
        .await?
        .ok_or_else(|| KohError::unreachable("connection closed before response"))
}

/// Spawns a dedicated reader task so callers can use `mpsc::Receiver::recv()` safely inside
/// `tokio::select!` without ever cancelling a half-read length-prefixed frame.
/// Stops promptly and drops the stream as soon as the caller drops the receiver.
pub fn spawn_msg_reader<T>(
    mut stream: RecvStream,
    max: usize,
) -> tokio::sync::mpsc::Receiver<Result<T>>
where
    T: DeserializeOwned + Send + 'static,
{
    let (tx, rx) = tokio::sync::mpsc::channel(16);
    tokio::spawn(async move {
        loop {
            let msg = tokio::select! {
                () = tx.closed() => break,
                res = recv_msg_opt::<T>(&mut stream, max) => res,
            };
            match msg {
                Ok(Some(msg)) => {
                    if tx.send(Ok(msg)).await.is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(err) => {
                    let _ = tx.send(Err(err)).await;
                    break;
                }
            }
        }
    });
    rx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failure_a_peer_tells_of_is_one_of_kohs_and_never_success() {
        // What a peer says went wrong becomes this process's exit code. It is one of the codes koh
        // has for a failure; anything else a peer may say, 0 first of all, is a plain failure.
        let told = [0, 1, 2, 3, 4, 5, 75, 124, 126, 127, 200, 255];
        let taken = [1, 1, 2, 3, 4, 1, 75, 124, 126, 127, 1, 255];
        for (said, code) in told.into_iter().zip(taken) {
            let (kind, message) = ("failed".to_string(), "it stopped".to_string());
            let answer = Reply::Err {
                code: said,
                kind: kind.clone(),
                message: message.clone(),
            };
            assert_eq!(answer.into_result().unwrap_err().code, Exit(code), "{said}");
            let failure = Failure {
                code: said,
                kind,
                message,
            };
            assert_eq!(KohError::from(failure).code, Exit(code), "{said}");
        }
    }
}
