//! Wire protocol for koh/21 over iroh QUIC bidirectional streams.
//! Every message is length-prefixed (`u32` big-endian) postcard with strict byte bounds.

use iroh::endpoint::{RecvStream, SendStream};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::{Exit, KohError, Result};

/// ALPN for the `koh/21` wire protocol.
pub const ALPN: &[u8] = b"koh/21";

pub const MAX_PROOF: usize = 512;
pub const MAX_CTRL: usize = 1 << 20; // 1 MiB
pub const MAX_FRAME: usize = 8 << 20; // 8 MiB
pub const MAX_CHUNK: usize = 256 << 10; // 256 KiB
/// The most bytes of one message on a session's stream, either way: a piece of what a viewer
/// drew, or of what was typed.
pub const VIEW_FRAME: usize = 16 << 10;

/// TLS-bound client authentication proof sent first on every connection's first stream.
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyProof {
    pub key: [u8; 32],
    pub signature: Vec<u8>,
}

/// Application-level QUIC close codes.
#[repr(u32)]
pub enum CloseCode {
    Refused = 1,
    Busy = 2,
    Protocol = 3,
}

/// Top-level RPC request sent at the start of a QUIC bidirectional stream.
#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    Exec {
        argv: Vec<String>,
        cwd: Option<String>,
    },
    Run {
        name: Option<String>,
        argv: Vec<String>,
        cwd: Option<String>,
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
        tail: usize,
        timeout_secs: Option<u64>,
    },
    Attach(Attach),
    /// The three that read a session's folder on the server (`pane`). `Sessions` is answered with
    /// a list of `SessionInfo`, in pieces as a text is: it is as long as the sessions that are
    /// kept make it.
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
}

/// Asks for a stream of a session, which is a fux pane on the server: answered `Ok`, then
/// `Attached`, then what the session's viewer draws (`ViewOutput`) against what is typed
/// (`ViewInput`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attach {
    /// The session. One that is not there is started under the name; with no name it is the
    /// newest that lives, or a new one (always, with `new` or a program).
    pub name: Option<String>,
    pub new: bool,
    /// The client's terminal: its size now, on every attach.
    pub size: ViewSize,
    pub argv: Vec<String>,
    pub cwd: Option<String>,
    /// The run this client views, on every attach but its first: the session's folder is
    /// that run or the attach is refused, and nothing is started. (A pane's `run`, as fux
    /// reads it: `fux::run_of`.)
    pub run: Option<u128>,
    /// A number the client chose when it started: its older stream on the run is ended first.
    pub client: u64,
    /// What the client's terminal is like, which the client asked it itself, once: no
    /// viewer asks across a link. Its `TERM`; the kitty keyboard flags it takes (0: it does
    /// not know the protocol, or did not say); and its colours, as lines of fux's `colours`
    /// file (`foreground #d0d0d0`), none if it told of none.
    pub term: String,
    pub keyboard: u8,
    pub colours: String,
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
    pub run: u128,
}

/// Initial server status reply to any `Request`.
#[derive(Debug, Serialize, Deserialize)]
pub enum Reply {
    Ok,
    Err { code: u8, message: String },
}

impl Reply {
    pub fn from_err(err: &KohError) -> Self {
        Self::Err {
            code: err.code.0,
            message: err.message.clone(),
        }
    }

    pub fn into_result(self) -> Result<()> {
        match self {
            Self::Ok => Ok(()),
            Self::Err { code, message } => Err(KohError::new(exit_of(code), message)),
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

/// Job summary returned by `Run` / `Jobs`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobInfo {
    pub name: String,
    pub state: String,
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
    pub exit: i32,
    pub tail: String,
    pub detail: String,
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

/// A terminal's size: in cells, and in pixels where the terminal says (pictures are scaled by
/// the cell's size; 0 is not said).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewSize {
    pub cols: u16,
    pub rows: u16,
    pub xpixel: u16,
    pub ypixel: u16,
}

impl ViewSize {
    /// As a pty takes it: a size fux would refuse is the nearest it takes (1 to 500 each way).
    pub fn tty(self) -> fuxix::Winsize {
        fuxix::Winsize {
            cols: self.cols.clamp(1, 500),
            rows: self.rows.clamp(1, 500),
            xpixel: self.xpixel,
            ypixel: self.ypixel,
        }
    }
}

/// What a client sends on a session's stream: what was typed at its terminal, as it was typed;
/// and its terminal's size when that changes.
#[derive(Debug, Serialize, Deserialize)]
pub enum ViewInput {
    Bytes(Vec<u8>),
    Resize(ViewSize),
}

/// What a server sends on a session's stream: what the session's viewer wrote to its terminal,
/// as it wrote it; and at the end the exit code, if the session ended (its program's) or its
/// user left it (0). A stream that ends without `Exit` was cut: the client comes again.
#[derive(Debug, Serialize, Deserialize)]
pub enum ViewOutput {
    Bytes(Vec<u8>),
    Exit(i32),
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

/// Write one length-prefixed frame whose body is already encoded.
pub async fn send_frame(stream: &mut SendStream, bytes: &[u8]) -> Result<()> {
    let len = u32::try_from(bytes.len()).map_err(|_| KohError::internal("message too large"))?;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|e| KohError::unreachable(format!("write length: {e}")))?;
    stream
        .write_all(bytes)
        .await
        .map_err(|e| KohError::unreachable(format!("write body: {e}")))?;
    Ok(())
}

/// Encode and write one length-prefixed postcard frame.
pub async fn send_msg<T: Serialize>(stream: &mut SendStream, value: &T, max: usize) -> Result<()> {
    send_frame(stream, &encode(value, max)?).await
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
            let answer = Reply::Err {
                code: said,
                message: "it stopped".to_string(),
            };
            assert_eq!(answer.into_result().unwrap_err().code, Exit(code), "{said}");
        }
    }
}
