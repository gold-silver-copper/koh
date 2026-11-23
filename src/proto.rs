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
        cell_w: u16,
        cell_h: u16,
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
            } => Err(KohError::new(Exit(code), kind_of(&kind), message)),
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

/// Result of `WaitJob` / `WaitSession`.
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
        Self::new(Exit(said.code), kind_of(&said.kind), said.message)
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

/// Image wire format matching frozen v1 `fux` pane folders (`pic-N.sixel` / `pic-N.png`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PictureKind {
    Sixel,
    Png,
}

impl PictureKind {
    pub fn ext(self) -> &'static str {
        match self {
            Self::Sixel => "sixel",
            Self::Png => "png",
        }
    }

    pub fn from_vt(fmt: fux_vt::PictureFormat) -> Self {
        match fmt {
            fux_vt::PictureFormat::Sixel => Self::Sixel,
            fux_vt::PictureFormat::Png => Self::Png,
        }
    }
}

/// Raw picture payload transferred once per picture ID on an attached stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PictureBlob {
    pub id: u32,
    pub kind: PictureKind,
    pub bytes: Vec<u8>,
}

/// One changed row in a `FrameDelta`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RowPatch {
    pub row: usize,
    pub screen: String,
    pub styled: String,
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
    pub pictures: String,
    pub cursor_row: usize,
    pub cursor_col: usize,
    pub cursor_shown: bool,
    pub cursor_shape: u8,
    pub cursor_colour: Option<[u8; 3]>,
    pub modes: String,
    pub title: String,
    pub marks: String,
    pub state: String,
    pub exit: Option<i32>,
    pub clipboard_seq: u64,
    pub clipboard: Option<Vec<u8>>,
    pub notice_seq: u64,
    pub notice: Option<String>,
}

/// Row-level incremental update relative to the previously sent `ScreenFrame`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameDelta {
    pub session_id: u32,
    pub generation: u64,
    pub changed_rows: Vec<RowPatch>,
    pub lines: Option<String>,
    pub links: Option<String>,
    pub pictures: Option<String>,
    pub cursor_row: usize,
    pub cursor_col: usize,
    pub cursor_shown: bool,
    pub cursor_shape: u8,
    pub cursor_colour: Option<[u8; 3]>,
    pub modes: Option<String>,
    pub title: Option<String>,
    pub marks: Option<String>,
    pub state: Option<String>,
    pub exit: Option<i32>,
    pub clipboard_seq: u64,
    pub clipboard: Option<Vec<u8>>,
    pub notice_seq: u64,
    pub notice: Option<String>,
}

/// Server-to-client messages on an interactive attach stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServerEvent {
    Full(ScreenFrame),
    Delta(FrameDelta),
    Picture(PictureBlob),
}

impl ScreenFrame {
    /// Computes a compact row-level delta against `prev` when geometry and screen plane match.
    /// Returns `None` when a full frame should be sent instead.
    pub fn diff(&self, prev: &Self) -> Option<FrameDelta> {
        if self.session_id != prev.session_id
            || self.cols != prev.cols
            || self.rows != prev.rows
            || self.alt != prev.alt
        {
            return None;
        }
        let cur_scr = split_rows(&self.screen);
        let prev_scr = split_rows(&prev.screen);
        let cur_sty = split_rows(&self.styled);
        let prev_sty = split_rows(&prev.styled);
        if cur_scr.len() != prev_scr.len() || cur_sty.len() != prev_sty.len() {
            return None;
        }
        let mut changed_rows = Vec::new();
        for row in 0..cur_scr.len().max(cur_sty.len()) {
            let cs = cur_scr.get(row).copied().unwrap_or_default();
            let ps = prev_scr.get(row).copied().unwrap_or_default();
            let cy = cur_sty.get(row).copied().unwrap_or_default();
            let py = prev_sty.get(row).copied().unwrap_or_default();
            if cs != ps || cy != py {
                changed_rows.push(RowPatch {
                    row,
                    screen: cs.to_string(),
                    styled: cy.to_string(),
                });
            }
        }
        // If almost the whole screen changed, a full frame is smaller/simpler.
        if self.rows > 4 && changed_rows.len() * 4 > self.rows * 3 {
            return None;
        }
        Some(FrameDelta {
            session_id: self.session_id,
            generation: self.generation,
            changed_rows,
            lines: (self.lines != prev.lines).then(|| self.lines.clone()),
            links: (self.links != prev.links).then(|| self.links.clone()),
            pictures: (self.pictures != prev.pictures).then(|| self.pictures.clone()),
            cursor_row: self.cursor_row,
            cursor_col: self.cursor_col,
            cursor_shown: self.cursor_shown,
            cursor_shape: self.cursor_shape,
            cursor_colour: self.cursor_colour,
            modes: (self.modes != prev.modes).then(|| self.modes.clone()),
            title: (self.title != prev.title).then(|| self.title.clone()),
            marks: (self.marks != prev.marks).then(|| self.marks.clone()),
            state: (self.state != prev.state).then(|| self.state.clone()),
            exit: self.exit,
            clipboard_seq: self.clipboard_seq,
            clipboard: self.clipboard.clone(),
            notice_seq: self.notice_seq,
            notice: self.notice.clone(),
        })
    }

    /// Applies `delta` in-place, returning the sorted row indices that changed.
    /// Rejects out-of-bounds row indices and guards against unbounded memory growth.
    pub fn apply_delta(&mut self, delta: FrameDelta) -> Vec<usize> {
        let max_rows = self.rows.min(fux_vt::SIZE_MAX);
        let mut changed_indices = Vec::with_capacity(delta.changed_rows.len().min(max_rows));
        if !delta.changed_rows.is_empty() && max_rows > 0 {
            let mut scr_rows: Vec<String> = split_rows(&self.screen)
                .into_iter()
                .take(max_rows)
                .map(str::to_string)
                .collect();
            let mut sty_rows: Vec<String> = split_rows(&self.styled)
                .into_iter()
                .take(max_rows)
                .map(str::to_string)
                .collect();
            let trailing_scr = self.screen.ends_with('\n');
            let trailing_sty = self.styled.ends_with('\n');
            for patch in delta.changed_rows {
                if patch.row >= max_rows {
                    continue;
                }
                let needed = patch.row.saturating_add(1);
                if needed > scr_rows.len() {
                    scr_rows.resize(needed, String::new());
                }
                if needed > sty_rows.len() {
                    sty_rows.resize(needed, String::new());
                }
                if let Some(slot) = scr_rows.get_mut(patch.row) {
                    *slot = patch.screen;
                }
                if let Some(slot) = sty_rows.get_mut(patch.row) {
                    *slot = patch.styled;
                }
                changed_indices.push(patch.row);
            }
            let new_screen = join_rows(&scr_rows, trailing_scr);
            let new_styled = join_rows(&sty_rows, trailing_sty);
            if new_screen.len().saturating_add(new_styled.len()) <= MAX_FRAME {
                self.screen = new_screen;
                self.styled = new_styled;
            }
        }
        self.session_id = delta.session_id;
        self.generation = delta.generation;
        if let Some(v) = delta.lines {
            self.lines = v;
        }
        if let Some(v) = delta.links {
            self.links = v;
        }
        if let Some(v) = delta.pictures {
            self.pictures = v;
        }
        self.cursor_row = delta.cursor_row.min(max_rows.saturating_sub(1));
        self.cursor_col = delta
            .cursor_col
            .min(self.cols.min(fux_vt::SIZE_MAX).saturating_sub(1));
        self.cursor_shown = delta.cursor_shown;
        self.cursor_shape = delta.cursor_shape;
        self.cursor_colour = delta.cursor_colour;
        if let Some(v) = delta.modes {
            self.modes = v;
        }
        if let Some(v) = delta.title {
            self.title = v;
        }
        if let Some(v) = delta.marks {
            self.marks = v;
        }
        if let Some(v) = delta.state {
            self.state = v;
        }
        self.exit = delta.exit;
        self.clipboard_seq = delta.clipboard_seq;
        self.clipboard = delta.clipboard;
        self.notice_seq = delta.notice_seq;
        self.notice = delta.notice;
        changed_indices
    }

    /// Clamps untrusted peer geometry and cursor coordinates to `fux_vt::SIZE_MAX`.
    pub fn clamp_bounds(&mut self) {
        self.cols = self.cols.min(fux_vt::SIZE_MAX);
        self.rows = self.rows.min(fux_vt::SIZE_MAX);
        self.cursor_row = self.cursor_row.min(self.rows.saturating_sub(1));
        self.cursor_col = self.cursor_col.min(self.cols.saturating_sub(1));
    }

    /// Parses all unique picture IDs referenced in the frozen v1 `pictures` listing.
    pub fn referenced_picture_ids(&self) -> Vec<u32> {
        let mut ids = Vec::new();
        for line in self.pictures.lines() {
            let Some(file) = line.split_whitespace().next() else {
                continue;
            };
            let Some(rest) = file.strip_prefix("pic-") else {
                continue;
            };
            let Some((num, _)) = rest.split_once('.') else {
                continue;
            };
            if let Ok(id) = num.parse::<u32>()
                && !ids.contains(&id)
            {
                ids.push(id);
            }
        }
        ids
    }
}

fn split_rows(text: &str) -> Vec<&str> {
    if text.is_empty() {
        return Vec::new();
    }
    text.strip_suffix('\n')
        .unwrap_or(text)
        .split('\n')
        .collect()
}

fn join_rows(rows: &[String], trailing_nl: bool) -> String {
    if rows.is_empty() {
        return String::new();
    }
    let mut out = rows.join("\n");
    if trailing_nl {
        out.push('\n');
    }
    out
}

/// Client-to-server events during an attached session.
#[derive(Debug, Serialize, Deserialize)]
pub enum ClientEvent {
    Input(Vec<u8>),
    Resize {
        cols: u16,
        rows: u16,
        cell_w: u16,
        cell_h: u16,
    },
    Colours(String),
    Detach,
    Keyboard(u8),
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

/// Spawns a dedicated reader task so callers can use `mpsc::Receiver::recv()` safely inside
/// `tokio::select!` without ever cancelling a half-read length-prefixed frame.
/// Stops promptly and drops the stream as soon as the caller drops the receiver.
pub fn spawn_msg_reader<T>(
    mut stream: RecvStream,
    max: usize,
) -> tokio::sync::mpsc::Receiver<Result<T>>
where
    T: for<'de> Deserialize<'de> + Send + 'static,
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
    fn frame_delta_round_trips_exact_screen_and_metadata() {
        let prev = ScreenFrame {
            session_id: 1,
            generation: 2,
            cols: 80,
            rows: 5,
            alt: false,
            screen: "line0\nline1\n\nline3\n\n".into(),
            styled: "line0\n\x1b[32mline1\x1b[m\n\nline3\n\n".into(),
            lines: "0\n\n".into(),
            links: String::new(),
            pictures: "pic-1.png 0 0 10 5 10 20\n".into(),
            cursor_row: 1,
            cursor_col: 5,
            cursor_shown: true,
            cursor_shape: 0,
            cursor_colour: None,
            modes: "paste".into(),
            title: "sh".into(),
            marks: String::new(),
            state: "running".into(),
            exit: None,
            clipboard_seq: 0,
            clipboard: None,
            notice_seq: 0,
            notice: None,
        };
        let mut curr = prev.clone();
        curr.generation = 4;
        curr.screen = "line0\nEDITED\n\nline3\n\n".into();
        curr.styled = "line0\n\x1b[31mEDITED\x1b[m\n\nline3\n\n".into();
        curr.cursor_col = 6;
        curr.cursor_colour = Some([0x11, 0x22, 0x33]);
        curr.clipboard_seq = 1;
        curr.clipboard = Some(b"copied".to_vec());
        curr.notice_seq = 1;
        curr.notice = Some(String::new());

        let delta = curr.diff(&prev).expect("expected delta");
        assert_eq!(delta.changed_rows.len(), 1);
        assert_eq!(delta.changed_rows.first().map(|r| r.row), Some(1));
        assert!(delta.pictures.is_none());
        assert!(delta.modes.is_none());

        let mut applied = prev.clone();
        let changed = applied.apply_delta(delta);
        assert_eq!(changed, vec![1]);
        assert_eq!(applied, curr);
        assert_eq!(applied.referenced_picture_ids(), vec![1]);

        // Geometry change forces full frame.
        let mut resized = curr.clone();
        resized.cols = 100;
        assert!(resized.diff(&curr).is_none());

        // Out-of-bounds / usize::MAX row indices in malformed deltas must be ignored without panic/OOM.
        let bad_delta = FrameDelta {
            session_id: 1,
            generation: 6,
            changed_rows: vec![
                RowPatch {
                    row: usize::MAX,
                    screen: "boom".into(),
                    styled: "boom".into(),
                },
                RowPatch {
                    row: 999,
                    screen: "oob".into(),
                    styled: "oob".into(),
                },
            ],
            lines: None,
            links: None,
            pictures: None,
            cursor_row: usize::MAX,
            cursor_col: usize::MAX,
            cursor_shown: true,
            cursor_shape: 0,
            cursor_colour: None,
            modes: None,
            title: None,
            marks: None,
            state: None,
            exit: None,
            clipboard_seq: 0,
            clipboard: None,
            notice_seq: 0,
            notice: None,
        };
        let mut safe = curr.clone();
        let changed = safe.apply_delta(bad_delta);
        assert!(changed.is_empty());
        assert_eq!(safe.screen, curr.screen);
        assert_eq!(safe.cursor_row, 4);
        assert_eq!(safe.cursor_col, 79);
    }
}
