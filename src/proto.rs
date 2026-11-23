//! Wire protocol for koh/18 over iroh QUIC bidirectional streams.
//! Every message is length-prefixed (`u32` big-endian) postcard with strict byte bounds.

use iroh::endpoint::{RecvStream, SendStream};
use serde::{Deserialize, Serialize};

use crate::{Exit, KohError, Result};

/// ALPN for koh v2 (fux-backed) protocol.
pub const ALPN: &[u8] = b"koh/18";

pub const MAX_PROOF: usize = 512;
pub const MAX_CTRL: usize = 1 << 20; // 1 MiB
pub const MAX_FRAME: usize = 8 << 20; // 8 MiB
pub const MAX_CHUNK: usize = 256 << 10; // 256 KiB

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
    WaitFile {
        path: String,
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
    },
    Sessions,
    Output {
        session: u32,
        last: bool,
    },
    WaitSession {
        session: u32,
        timeout_secs: Option<u64>,
    },
    Attach {
        session: Option<u32>,
        new: bool,
        cols: u16,
        rows: u16,
        argv: Vec<String>,
        cwd: Option<String>,
    },
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
            } => {
                let kind: &'static str = match kind.as_str() {
                    "refused" => "refused",
                    "usage" => "usage",
                    "unreachable" => "unreachable",
                    "timeout" => "timeout",
                    "busy" => "busy",
                    "not_found" => "not_found",
                    "cannot_start" => "cannot_start",
                    "failed" => "failed",
                    _ => "remote",
                };
                Err(KohError::new(Exit(code), kind, message))
            }
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

/// Result of `WaitJob` / `WaitFile` / `WaitSession`.
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

/// Interactive `fux`-backed session metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub id: u32,
    pub attached: bool,
    pub state: String,
    pub cols: usize,
    pub rows: usize,
    pub title: String,
    pub running_command: bool,
    pub last_exit: Option<u8>,
    pub age_secs: u64,
    pub pane_dir: String,
}

/// Snapshot of a remote `fux` pane's frozen v1 screen state pushed to attached clients.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScreenFrame {
    pub session_id: u32,
    pub generation: u64,
    pub cols: usize,
    pub rows: usize,
    pub alt: bool,
    pub screen: String,
    pub styled: String,
    pub lines: String,
    pub links: String,
    pub cursor_row: usize,
    pub cursor_col: usize,
    pub cursor_shown: bool,
    pub cursor_shape: u8,
    pub modes: String,
    pub title: String,
    pub marks: String,
    pub state: String,
    pub exit: Option<i32>,
}

/// Client-to-server events during an attached session.
#[derive(Debug, Serialize, Deserialize)]
pub enum ClientEvent {
    Input(Vec<u8>),
    Resize { cols: u16, rows: u16 },
    Detach,
}

/// Encode and write one length-prefixed postcard frame.
pub async fn send_msg<T: Serialize>(stream: &mut SendStream, value: &T, max: usize) -> Result<()> {
    let bytes =
        postcard::to_allocvec(value).map_err(|e| KohError::internal(format!("encode: {e}")))?;
    if bytes.len() > max {
        return Err(KohError::internal(format!(
            "message exceeds bound ({} > {max})",
            bytes.len()
        )));
    }
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
pub async fn recv_msg_opt<T: for<'de> Deserialize<'de>>(
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
    let val =
        postcard::from_bytes(&buf).map_err(|e| KohError::failed(format!("decode message: {e}")))?;
    Ok(Some(val))
}

/// Read and decode one required frame.
pub async fn recv_msg<T: for<'de> Deserialize<'de>>(
    stream: &mut RecvStream,
    max: usize,
) -> Result<T> {
    recv_msg_opt(stream, max)
        .await?
        .ok_or_else(|| KohError::unreachable("connection closed before response"))
}
