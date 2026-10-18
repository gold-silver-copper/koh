//! The koh/7 shell protocol: what a session's connection carries after its opening request
//! ([`crate::request`]).
//!
//! The client writes [`ClientMsg`]s on two uni streams, its first (the request's) for control and
//! one for input, each a 4-byte big-endian length followed by its postcard encoding. After the
//! [`Attached`](crate::request::Attached) that admits the client, the server sends every screen update as a
//! [`Frame`] on its own uni stream: a tag, the base's number, then the postcard encoding
//! DEFLATE-compressed against the base screen ([`FrameEncoder`]); history rows go the same way,
//! without a base, each reply naming the request it answers. Frames diff against a frame the
//! client has (its delivery is its acknowledgement), so a lost or reset frame only delays the
//! screen until the next one. A refusal, as any close, says why by its code ([`Close`]).
//!
//! Everything here is pure: the connection loops move bytes, this module turns them into messages
//! and rejects anything oversized or malformed.

use std::sync::Arc;
use std::time::Duration;

use miniz_oxide::deflate::core::CompressorOxide;
use serde::{Deserialize, Serialize};

use crate::events::{check_events, InputEvent, WireColours};
use crate::terminal::{
    HistoryReply, HistoryRequest, RowEncodings, ScreenDiff, Size, TerminalScreen, MAX_HISTORY_REPLY,
};

/// A frame number. Frame 0 is the blank default screen both ends start from; it is never sent.
/// Real frames count from 1 on each connection.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct FrameNum(pub u64);

impl FrameNum {
    /// The blank default screen.
    pub const BLANK: Self = Self(0);

    /// The frame after this one. Saturates: a connection cannot send `u64::MAX` frames, and a
    /// saturated counter keeps frames ordered rather than wrapping back below the ones sent.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

/// An input sequence number: which [`ClientMsg::Keys`] on this connection. The first is 1; 0
/// means "no input yet".
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct InputSeq(pub u64);

impl InputSeq {
    /// The sequence number after this one (saturating, like [`FrameNum::next`]).
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

/// How often, at most, a session's PTY modes go unread while a client is attached.
///
/// A program that turns echo off after printing its prompt is known to the client within about
/// this, plus the link's latency. The client keeps keys typed at a fresh prompt from showing for
/// twice this.
pub const TTY_TICK: Duration = Duration::from_millis(100);

/// Most bytes in one encoded client message: a whole paste, and a full message of keys beside it.
pub const MAX_CLIENT_MESSAGE: usize = crate::events::MAX_PASTE + 64 * 1024;

/// Most bytes in a frame, both compressed on the stream and inflated. A full repaint of a
/// 1000×1000 screen with varied styles is several MiB.
pub const MAX_FRAME: usize = 16 * 1024 * 1024;

/// How many recent screens each end keeps.
///
/// The client keeps its last applied frames, the server the frames it sent since the newest one
/// acknowledged. A constant, so neither end's memory grows with what the peer sends or withholds.
pub const FRAME_WINDOW: usize = 16;

/// Most cells the recent screens an end keeps may hold, a row several of them share counted once:
/// one screen of the largest size a client may ask for (`MAX_DIM`²).
///
/// [`FRAME_WINDOW`] alone is no memory bound when one screen can be a million cells (about 32 MB):
/// sixteen of them are half a gigabyte, which a hostile peer, or one on a huge terminal, could
/// make the other end hold by resizing. Past this the oldest screens are dropped, as past the
/// window; a dropped screen is only a base the peer can no longer have a frame diffed against.
pub const WINDOW_CELLS: usize = 1_000_000;

/// A frame's number and the screen it brings the client to. Screens are shared, not copied, by
/// every frame that shows them.
#[derive(Clone, Debug, Default)]
pub struct FrameScreen {
    pub num: FrameNum,
    pub screen: Arc<TerminalScreen>,
}

/// The server sends a frame at least this often, even when nothing changed, so the client can tell
/// a quiet session from a dead link.
pub const HEARTBEAT: Duration = Duration::from_secs(3);

/// Why a connection was closed: its QUIC application close code.
///
/// The code is the only part read; the reason bytes a peer chooses are never shown, only
/// [`Close::text`]. Code 0 is none of these: an endpoint closing (a server restarting) uses it.
/// Only `NotAuthorized` and `NoSuchSession` are for good: a shell's client redials after the
/// others but `SessionEnded`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Close {
    NotAuthorized = 1,
    /// The peer broke the protocol, or made no request in time.
    ProtocolError = 2,
    /// The hosted program exited, and the client was sent its final screen.
    SessionEnded = 3,
    /// The server holds its most sessions, and the client asked for a new one.
    AtCapacity = 4,
    /// The session's program, or the command asked for, could not start, or the server is
    /// shutting down.
    CouldNotStart = 5,
    /// The session asked for by number is not the client's, or is gone.
    NoSuchSession = 6,
}

impl Close {
    pub const fn code(self) -> u32 {
        self as u32
    }

    /// The reason close code `code` gives, if it is one of these.
    pub const fn from_code(code: u64) -> Option<Self> {
        Some(match code {
            1 => Self::NotAuthorized,
            2 => Self::ProtocolError,
            3 => Self::SessionEnded,
            4 => Self::AtCapacity,
            5 => Self::CouldNotStart,
            6 => Self::NoSuchSession,
            _ => return None,
        })
    }

    /// What it says, for a person.
    pub const fn text(self) -> &'static str {
        match self {
            Self::NotAuthorized => "not authorized (is this client on the server's allowlist?)",
            Self::ProtocolError => "protocol error",
            Self::SessionEnded => "session ended",
            Self::AtCapacity => "server at session capacity",
            Self::CouldNotStart => "the server could not start the program",
            Self::NoSuchSession => "no such session (it ended, or the server restarted)",
        }
    }
}

impl std::fmt::Display for Close {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.text())
    }
}

impl std::error::Error for Close {}

/// The least gap the server leaves between frames.
///
/// Enough to take a burst of output as one frame, little enough not to be felt. How many frames go
/// is set by what the link takes, not by a timer (`server::ServerConn::poll_frame`).
pub const FRAME_FLOOR: Duration = Duration::from_millis(5);

/// The RTT assumed before the path has measured one (QUIC's initial RTT).
const INITIAL_RTT: Duration = Duration::from_millis(333);

/// How long an unacknowledged frame, or unconfirmed input, waits before the sender acts on its own.
///
/// A round trip, the frame floor and the acknowledgement's delay. The server then resends its
/// newest screen as a new frame, and the client sends a probe, instead of waiting out QUIC's
/// exponentially backed-off probe timeout, which on a lossy, jittery path is several round trips.
pub fn retry_after(rtt: Option<Duration>) -> Duration {
    rtt.unwrap_or(INITIAL_RTT)
        .saturating_add(FRAME_FLOOR)
        .saturating_add(ACK_DELAY)
}

/// The longest a peer's QUIC stack waits before acknowledging what it got (QUIC's default
/// `max_ack_delay`). A frame's delivery is its acknowledgement, which may come this much after the
/// round trip.
pub const ACK_DELAY: Duration = Duration::from_millis(25);

/// Most history requests a client may have waiting for an answer; one more is a protocol error.
/// The server answers one at a time, so a client cannot make it send faster than the link takes.
pub const MAX_PENDING_HISTORY: usize = 8;

/// DEFLATE level for frames. Screen diffs are very compressible (runs of spaces, repeated
/// styles), so a mid level gets most of the ratio at little CPU.
const COMPRESSION_LEVEL: u8 = 6;

/// A message on the client's stream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientMsg {
    /// The client's window is now `size`: its `n`th resize on the connection. It goes on both
    /// streams: on the control one, to wait for no input, and among the input, so nothing typed
    /// after it overtakes it. The server applies each `n` once, and none older than one applied.
    Resize { n: u32, size: Size },
    /// The client applied `frame`; later frames may diff against it. A frame's delivery already
    /// says so, so the client sends this only to nudge: a later packet that lets QUIC detect a lost
    /// one and retransmit it at once.
    Ack { frame: FrameNum },
    /// The client got a frame whose base it does not hold; the next frame must diff against
    /// [`FrameNum::BLANK`].
    Resync,
    /// The client asks for history rows it lacks (see [`HistoryRequest`]). The server answers each,
    /// with no rows if it holds none, one at a time and at a lower priority than frames; the
    /// reply carries the request's id.
    History(HistoryRequest),
    /// Input the client decoded: keys, mouse events, focus changes and pastes, in order, at most
    /// [`MAX_EVENTS`](crate::events::MAX_EVENTS). The server encodes each for the program as it
    /// asked.
    Keys {
        seq: InputSeq,
        #[serde(
            deserialize_with = "crate::bounded::at_most::<{ crate::events::MAX_EVENTS }, _, _>"
        )]
        events: Vec<InputEvent>,
    },
    /// What the user's terminal said of its colours: sent after connecting, on every reconnect,
    /// and when the terminal reports a new scheme, unless the user turned it off.
    Colours(WireColours),
}

/// Which of the client's two streams a message goes on. Control messages have one of their own,
/// so none waits behind input a slow program has not read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stream {
    Input,
    Control,
}

impl ClientMsg {
    /// The stream it goes on.
    pub const fn stream(&self) -> Stream {
        match self {
            Self::Keys { .. } | Self::Colours(_) | Self::Resize { .. } => Stream::Input,
            Self::Ack { .. } | Self::Resync | Self::History(_) => Stream::Control,
        }
    }
}

/// A screen update: the change from frame `base` to frame `num`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Frame {
    pub num: FrameNum,
    pub base: FrameNum,
    /// The newest input the server considers reflected on this screen.
    pub echo_ack: InputSeq,
    pub diff: ScreenDiff,
}

/// Why bytes from the peer were rejected.
#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    #[error("message of {len} bytes exceeds the {max}-byte limit")]
    TooLarge { len: usize, max: usize },
    #[error("stream ended inside a message")]
    Truncated,
    #[error("malformed message: {0}")]
    Malformed(#[from] postcard::Error),
    #[error("could not inflate the frame (corrupt, or larger than {MAX_FRAME} bytes)")]
    Inflate,
    #[error(
        "history rows where a frame was expected, or a frame on another base than its stream's"
    )]
    NotAFrame,
    #[error("a server stream of an unknown kind")]
    UnknownStream,
    #[error("a frame's rows out of order or repeated")]
    Unordered,
    #[error("more than {MAX_PENDING_HISTORY} history requests waiting")]
    TooManyRequests,
    #[error("input no terminal sends: {0}")]
    BadInput(&'static str),
}

/// Refuse `len` past `max` as [`ProtoError::TooLarge`].
fn at_most(len: usize, max: usize) -> Result<(), ProtoError> {
    (len <= max)
        .then_some(())
        .ok_or(ProtoError::TooLarge { len, max })
}

impl ClientMsg {
    /// Refuse input no terminal sends, which neither end sends nor takes.
    fn check(&self) -> Result<(), ProtoError> {
        match self {
            Self::Keys { events, .. } => check_events(events),
            Self::Colours(colours) => colours.check(),
            Self::Resize { .. } | Self::Ack { .. } | Self::Resync | Self::History(_) => Ok(()),
        }
        .map_err(ProtoError::BadInput)
    }
}

/// Encode one client message with its length prefix.
pub fn encode_client(msg: &ClientMsg) -> Result<Vec<u8>, ProtoError> {
    msg.check()?;
    // The body goes straight after a placeholder for its length.
    let mut out = postcard::to_extend(msg, vec![0; 4])?;
    let body = out.len().saturating_sub(4);
    at_most(body, MAX_CLIENT_MESSAGE)?;
    if let Some(prefix) = out.first_chunk_mut::<4>() {
        *prefix = u32::try_from(body).unwrap_or(u32::MAX).to_be_bytes();
    }
    Ok(out)
}

/// Splits the client's stream back into messages, however its bytes arrive.
#[derive(Debug, Default)]
pub struct ClientDecoder {
    buf: Vec<u8>,
    /// How many bytes at the front of `buf` were already decoded. They are dropped in one move
    /// once no complete message is left, not after every message: one read can hold thousands.
    start: usize,
}

impl ClientDecoder {
    /// Append bytes read from the stream.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// The bytes not decoded yet.
    fn pending(&self) -> &[u8] {
        self.buf.get(self.start..).unwrap_or_default()
    }

    /// The next complete message, or `None` if more bytes are needed. An error means the peer
    /// broke the protocol; the caller closes the connection.
    pub fn next_msg(&mut self) -> Result<Option<ClientMsg>, ProtoError> {
        let Some((len, rest)) = self.pending().split_first_chunk::<4>() else {
            self.compact();
            return Ok(None);
        };
        let len = usize::try_from(u32::from_be_bytes(*len)).unwrap_or(usize::MAX);
        at_most(len, MAX_CLIENT_MESSAGE)?;
        let Some(body) = rest.get(..len) else {
            self.compact();
            return Ok(None);
        };
        let msg: ClientMsg = postcard::from_bytes(body)?;
        msg.check()?;
        // The header and body were just read, so `start + 4 + len` is within the buffer.
        self.start = self
            .start
            .saturating_add(len)
            .saturating_add(4)
            .min(self.buf.len());
        Ok(Some(msg))
    }

    /// Drop the decoded bytes, moving what is left of a partial message to the front.
    fn compact(&mut self) {
        self.buf.drain(..self.start);
        self.start = 0;
    }

    /// The stream ended: fine between messages, a protocol error inside one.
    pub fn finish(&self) -> Result<(), ProtoError> {
        self.pending()
            .is_empty()
            .then_some(())
            .ok_or(ProtoError::Truncated)
    }
}

/// A message on one of the server's streams, as the stream's reader takes it, still compressed: a
/// frame to inflate against its base, or history rows ([`decode_history`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerMsg {
    /// A frame diffed against frame `base`, changing `rows`, whose compressed `body` inflates only
    /// against that screen's dictionary of those rows ([`decode_frame_body`]).
    Frame {
        base: FrameNum,
        rows: Vec<u16>,
        body: Vec<u8>,
    },
    History(Vec<u8>),
}

/// The first byte of a server stream: what it carries.
const TAG_FRAME: u8 = 0;
const TAG_HISTORY: u8 = 1;

/// Encodes the server's streams, keeping rows' encodings for the next frame's dictionary, and one
/// compressor, reset for each stream rather than made anew.
pub struct FrameEncoder {
    encodings: RowEncodings,
    compressor: Box<CompressorOxide>,
}

impl Default for FrameEncoder {
    fn default() -> Self {
        Self {
            encodings: RowEncodings::default(),
            compressor: Box::new(compressor()),
        }
    }
}

impl FrameEncoder {
    /// `frame` encoded for its stream: its tag, its base's number, the rows it changes, then the
    /// frame compressed against `base`, the screen of frame `frame.base`.
    ///
    /// The compressor starts from a dictionary of the rows the frame changes as `base` has them
    /// ([`TerminalScreen::dictionary`]), so a changed row compresses against what it was: a
    /// ticking clock or a typed character costs a few bytes. Both ends hold the base screen, the
    /// stream names the rows, and the client refuses a frame whose base it does not hold, so the
    /// dictionaries cannot disagree. The blank screen's dictionary is empty.
    pub fn encode(&mut self, frame: &Frame, base: &TerminalScreen) -> Result<Vec<u8>, ProtoError> {
        let rows: Vec<u16> = frame.diff.rows.iter().map(|row| row.row).collect();
        let dictionary = dictionary_for(frame.base, base, &rows, &mut self.encodings);
        let raw = postcard::to_allocvec(frame)?;
        let mut out = postcard::to_extend(&frame.base.0, vec![TAG_FRAME])?;
        out = postcard::to_extend(&rows, out)?;
        out.extend_from_slice(&compress(&mut self.compressor, &dictionary, &raw));
        Ok(out)
    }

    /// History rows encoded for their stream.
    pub fn encode_history(&mut self, reply: &HistoryReply) -> Result<Vec<u8>, ProtoError> {
        let raw = postcard::to_allocvec(reply)?;
        let mut out = vec![TAG_HISTORY];
        out.extend_from_slice(&compress(&mut self.compressor, &[], &raw));
        Ok(out)
    }
}

/// The dictionary a frame on `base`, whose screen is `screen`, changing `rows`, is compressed
/// against.
pub fn dictionary_for(
    base: FrameNum,
    screen: &TerminalScreen,
    rows: &[u16],
    encodings: &mut RowEncodings,
) -> Vec<u8> {
    if base == FrameNum::BLANK {
        Vec::new()
    } else {
        screen.dictionary(rows, encodings)
    }
}

/// A raw DEFLATE compressor at [`COMPRESSION_LEVEL`].
fn compressor() -> CompressorOxide {
    use miniz_oxide::deflate::core::create_comp_flags_from_zip_params;
    CompressorOxide::new(create_comp_flags_from_zip_params(
        COMPRESSION_LEVEL.into(),
        -15,
        0,
    ))
}

/// `raw` compressed as if it followed `dictionary`, by `compressor` reset first.
fn compress(compressor: &mut CompressorOxide, dictionary: &[u8], raw: &[u8]) -> Vec<u8> {
    use miniz_oxide::deflate::core::{compress_to_output, TDEFLFlush};
    compressor.reset();
    if !dictionary.is_empty() {
        let _ = compress_to_output(compressor, dictionary, TDEFLFlush::Sync, |_| true);
    }
    let mut out = Vec::with_capacity(raw.len().div_euclid(2).saturating_add(64));
    let _ = compress_to_output(compressor, raw, TDEFLFlush::Finish, |bytes| {
        out.extend_from_slice(bytes);
        true
    });
    out
}

/// What [`compress`] compressed after `dictionary`, at most `limit` bytes of it, or `None`
/// if `body` is corrupt or inflates past the limit. The dictionary is the window the body's
/// back-references reach into; nothing reaches before it.
fn inflate_with(dictionary: &[u8], body: &[u8], limit: usize) -> Option<Vec<u8>> {
    use miniz_oxide::inflate::core::inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF;
    use miniz_oxide::inflate::core::{decompress, DecompressorOxide};
    use miniz_oxide::inflate::TINFLStatus;
    let start = dictionary.len();
    let most = start.checked_add(limit)?;
    let mut out = dictionary.to_vec();
    out.resize(
        start
            .saturating_add(body.len().saturating_mul(4).max(1024))
            .min(most),
        0,
    );
    let mut decompressor = DecompressorOxide::new();
    let mut input = body;
    let mut pos = start;
    loop {
        let (status, used, wrote) = decompress(
            &mut decompressor,
            input,
            &mut out,
            pos,
            TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
        );
        input = input.get(used..)?;
        pos = pos.checked_add(wrote)?;
        // The status is `#[non_exhaustive]`: anything but done or a full buffer is a failure.
        if matches!(status, TINFLStatus::Done) {
            break;
        }
        if !matches!(status, TINFLStatus::HasMoreOutput) || out.len() >= most {
            return None;
        }
        let grown = out.len().saturating_mul(2).min(most);
        out.resize(grown, 0);
    }
    out.truncate(pos);
    Some(out.split_off(start))
}

/// Read a server stream: a frame's base and compressed body, which [`decode_frame_body`] inflates
/// once the base is found, or history rows, which [`decode_history`] inflates.
pub fn decode_server(bytes: &[u8]) -> Result<ServerMsg, ProtoError> {
    at_most(bytes.len(), MAX_FRAME)?;
    match bytes.split_first() {
        Some((&TAG_FRAME, rest)) => {
            let (base, rest) = postcard::take_from_bytes::<u64>(rest)?;
            let (rows, body) = take_rows(rest)?;
            Ok(ServerMsg::Frame {
                base: FrameNum(base),
                rows,
                body: body.to_vec(),
            })
        }
        Some((&TAG_HISTORY, rest)) => Ok(ServerMsg::History(rest.to_vec())),
        _ => Err(ProtoError::UnknownStream),
    }
}

/// The rows a frame's stream names, and what follows: a count, at most [`MAX_DIM`], then each row,
/// strictly ascending, as a diff lists them. Read one by one, so a hostile count allocates nothing
/// it does not carry, and a row named twice (whose dictionary would repeat it) is refused.
fn take_rows(bytes: &[u8]) -> Result<(Vec<u16>, &[u8]), ProtoError> {
    let (count, mut rest) = postcard::take_from_bytes::<u32>(bytes)?;
    let count = usize::try_from(count).unwrap_or(usize::MAX);
    at_most(count, usize::from(crate::terminal::MAX_DIM))?;
    let mut rows: Vec<u16> = Vec::with_capacity(count);
    for _ in 0..count {
        let (row, after) = postcard::take_from_bytes::<u16>(rest)?;
        if rows.last().is_some_and(|&last| last >= row) {
            return Err(ProtoError::Unordered);
        }
        rows.push(row);
        rest = after;
    }
    Ok((rows, rest))
}

/// Inflate a frame's body against its base's dictionary ([`dictionary_for`]) and decode it. A
/// frame that names another base than its stream did is refused.
pub fn decode_frame_body(
    base: FrameNum,
    body: &[u8],
    dictionary: &[u8],
) -> Result<Frame, ProtoError> {
    let raw = inflate_with(dictionary, body, MAX_FRAME).ok_or(ProtoError::Inflate)?;
    let frame: Frame = postcard::from_bytes(&raw)?;
    (frame.base == base)
        .then_some(frame)
        .ok_or(ProtoError::NotAFrame)
}

/// Inflate history rows, no further than a legal reply goes ([`MAX_HISTORY_REPLY`]), and decode
/// them.
pub fn decode_history(body: &[u8]) -> Result<HistoryReply, ProtoError> {
    let raw = inflate_with(&[], body, MAX_HISTORY_REPLY).ok_or(ProtoError::Inflate)?;
    Ok(postcard::from_bytes(&raw)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_frame(frame: &Frame, base: &TerminalScreen) -> Result<Vec<u8>, ProtoError> {
        FrameEncoder::default().encode(frame, base)
    }

    /// Decode a stream that must hold a frame on `screen`, the screen of the frame's base.
    fn decode_frame(bytes: &[u8], screen: &TerminalScreen) -> Result<Frame, ProtoError> {
        match decode_server(bytes)? {
            ServerMsg::Frame { base, rows, body } => {
                let dictionary = dictionary_for(base, screen, &rows, &mut RowEncodings::default());
                decode_frame_body(base, &body, &dictionary)
            }
            ServerMsg::History(_) => Err(ProtoError::NotAFrame),
        }
    }

    #[test]
    fn close_codes_round_trip_and_0_is_none_of_them() {
        for code in 1..=6 {
            assert_eq!(
                Close::from_code(code).map(|c| u64::from(c.code())),
                Some(code)
            );
        }
        assert_eq!(Close::from_code(0), None);
        assert_eq!(Close::from_code(7), None);
    }

    fn frame() -> Frame {
        let screen = TerminalScreen::from_bytes(24, 80, b"hello \x1b[31mworld\x1b[m");
        Frame {
            num: FrameNum(7),
            base: FrameNum(5),
            echo_ack: InputSeq(3),
            diff: screen.diff_from(&TerminalScreen::default()),
        }
    }

    fn decode_all(bytes: &[u8]) -> Result<Vec<ClientMsg>, ProtoError> {
        let mut decoder = ClientDecoder::default();
        decoder.push(bytes);
        let mut out = Vec::new();
        while let Some(msg) = decoder.next_msg()? {
            out.push(msg);
        }
        decoder.finish()?;
        Ok(out)
    }

    #[test]
    fn client_messages_round_trip_whatever_the_chunking() {
        let msgs = vec![
            ClientMsg::Keys {
                seq: InputSeq(1),
                events: vec![InputEvent::Focus(true)],
            },
            ClientMsg::Resize {
                n: 1,
                size: Size::new(50, 132),
            },
            ClientMsg::Ack { frame: FrameNum(9) },
            ClientMsg::Resync,
            ClientMsg::Keys {
                seq: InputSeq(2),
                events: vec![InputEvent::Paste("\x1b".repeat(crate::events::MAX_PASTE))],
            },
        ];
        let stream: Vec<u8> = msgs
            .iter()
            .flat_map(|m| encode_client(m).unwrap())
            .collect();
        assert_eq!(decode_all(&stream).unwrap(), msgs);
        // One byte at a time: the decoder waits for whole messages.
        let mut decoder = ClientDecoder::default();
        let mut out = Vec::new();
        for byte in &stream {
            decoder.push(std::slice::from_ref(byte));
            while let Some(msg) = decoder.next_msg().unwrap() {
                out.push(msg);
            }
        }
        decoder.finish().unwrap();
        assert_eq!(out, msgs);
    }

    #[test]
    fn a_read_of_many_tiny_messages_decodes_them_all_and_leaves_the_buffer_empty() {
        let msg = ClientMsg::Resize {
            n: 1,
            size: Size::new(1, 2),
        };
        let resize = encode_client(&msg).unwrap();
        let count = (16 * 1024_usize).div_euclid(resize.len());
        let mut decoder = ClientDecoder::default();
        decoder.push(&resize.repeat(count));
        assert!(decoder.next_msg().unwrap().is_some());
        assert_eq!(
            decoder.buf.len(),
            resize.len() * count,
            "decoding a message does not move the rest of the read"
        );
        let mut decoded = 1;
        while let Some(next) = decoder.next_msg().unwrap() {
            assert_eq!(next, msg);
            decoded += 1;
        }
        assert_eq!(decoded, count);
        assert!(decoder.buf.is_empty(), "{} bytes left", decoder.buf.len());
        decoder.finish().unwrap();
        // A partial message is kept, at the front, for the next read.
        decoder.push(&resize[..3]);
        assert!(decoder.next_msg().unwrap().is_none());
        decoder.push(&resize[3..]);
        assert_eq!(decoder.next_msg().unwrap(), Some(msg));
    }

    #[test]
    fn oversized_client_messages_are_rejected_before_buffering() {
        let too_long = ClientMsg::Keys {
            seq: InputSeq(1),
            events: vec![InputEvent::Paste("a".repeat(MAX_CLIENT_MESSAGE)); 1],
        };
        assert!(encode_client(&too_long).is_err());
        // A header announcing more than the cap is refused as soon as the header arrives.
        let mut decoder = ClientDecoder::default();
        let len = u32::try_from(MAX_CLIENT_MESSAGE + 1).unwrap();
        decoder.push(&len.to_be_bytes());
        assert!(matches!(
            decoder.next_msg(),
            Err(ProtoError::TooLarge { .. })
        ));
    }

    /// Input no terminal sends, built by hand inside a legal envelope (`encode_client` refuses to
    /// build it): the decoder refuses it, and the server closes the connection.
    #[test]
    fn keys_and_colours_no_terminal_sends_are_refused() {
        use crate::events::{
            WireButton, WireKey, WireKeyCode, WireKitty, WireMouse, WireMouseAction, MAX_EVENTS,
            MAX_PASTE, PALETTE,
        };
        let framed = |body: Vec<u8>| {
            let mut stream = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
            stream.extend_from_slice(&body);
            stream
        };
        let raw = |msg: &ClientMsg| framed(postcard::to_allocvec(msg).unwrap());
        let keys = |events: Vec<InputEvent>| ClientMsg::Keys {
            seq: InputSeq(1),
            events,
        };
        let key = |key, mods, kitty| InputEvent::Key(WireKey { key, mods, kitty });
        let bad = [
            keys(vec![key(WireKeyCode::Char('a'), 0x08, None)]),
            keys(vec![key(
                WireKeyCode::Char('a'),
                0,
                Some(WireKitty {
                    code: Some(0xdfff),
                    shifted: None,
                    base: None,
                    mods: 0,
                }),
            )]),
            keys(vec![key(
                WireKeyCode::Char('a'),
                0,
                Some(WireKitty {
                    code: None,
                    shifted: Some(0x11_0000),
                    base: None,
                    mods: 0,
                }),
            )]),
            keys(vec![InputEvent::Mouse(WireMouse {
                action: WireMouseAction::Press(WireButton::Left),
                mods: 0x10,
                row: 0,
                col: 0,
            })]),
            keys(vec![InputEvent::Paste("x".repeat(MAX_PASTE + 1))]),
            keys(vec![InputEvent::Focus(true); MAX_EVENTS + 1]),
            ClientMsg::Colours(WireColours {
                palette: vec![None; PALETTE + 1],
                ..WireColours::default()
            }),
        ];
        for msg in &bad {
            assert!(encode_client(msg).is_err(), "{msg:?}");
            assert!(decode_all(&raw(msg)).is_err(), "{msg:?}");
        }
        // A code that is no character at all, or no function key's, does not even decode.
        let f35 = WireKeyCode::F(35.try_into().unwrap());
        for (code, at, byte) in [
            (WireKeyCode::Char('a'), b'a', 0xff),
            (f35, 35, 0),
            (f35, 35, 36),
        ] {
            let mut body = postcard::to_allocvec(&keys(vec![key(code, 0, None)])).unwrap();
            let at = body.iter().rposition(|&b| b == at).unwrap();
            body[at] = byte;
            assert!(decode_all(&framed(body)).is_err(), "{code:?} as {byte}");
        }
        // What a terminal sends goes through, both ways.
        let good = [
            keys(vec![
                key(WireKeyCode::Char('é'), 7, None),
                key(f35, 0, None),
                InputEvent::Paste("x".repeat(MAX_PASTE)),
            ]),
            keys(vec![InputEvent::Focus(false); MAX_EVENTS]),
            ClientMsg::Colours(WireColours {
                foreground: Some([1, 2, 3]),
                background: None,
                palette: vec![Some([0, 0, 0]); PALETTE],
                scheme: None,
            }),
        ];
        for msg in good {
            let stream = encode_client(&msg).unwrap();
            assert_eq!(decode_all(&stream).unwrap(), vec![msg]);
        }
    }

    #[test]
    fn truncated_and_garbage_client_streams_are_errors() {
        let stream = encode_client(&ClientMsg::Resize {
            n: 1,
            size: Size::new(1, 2),
        })
        .unwrap();
        for cut in 1..stream.len() {
            assert!(
                matches!(decode_all(&stream[..cut]), Err(ProtoError::Truncated)),
                "cut at {cut}"
            );
        }
        let garbage = [0, 0, 0, 3, 0xff, 0xff, 0xff];
        assert!(decode_all(&garbage).is_err());
    }

    #[test]
    fn a_frame_compresses_against_its_base_and_inflates_only_against_it() {
        let base =
            TerminalScreen::from_bytes(24, 80, &b"a line of text that repeats\r\n".repeat(20));
        let mut target_bytes = b"a line of text that repeats\r\n".repeat(20);
        target_bytes.extend_from_slice(b"\x1b[3;1Ha line of text that repeatz");
        let target = TerminalScreen::from_bytes(24, 80, &target_bytes);
        let frame = Frame {
            num: FrameNum(8),
            base: FrameNum(7),
            echo_ack: InputSeq(0),
            diff: target.diff_from(&base),
        };
        let against_base = encode_frame(&frame, &base).unwrap();
        // On the blank base, whose dictionary is empty.
        let alone = encode_frame(
            &Frame {
                base: FrameNum::BLANK,
                ..frame.clone()
            },
            &base,
        )
        .unwrap();
        assert!(
            against_base.len() < alone.len(),
            "{} against the base, {} alone",
            against_base.len(),
            alone.len()
        );
        assert_eq!(decode_frame(&against_base, &base).unwrap(), frame);
        // Another screen's dictionary inflates to something else, or nothing.
        let other = TerminalScreen::from_bytes(24, 80, b"another screen");
        assert!(decode_frame(&against_base, &other).map_or(true, |f| f != frame));
        // A frame naming another base than its stream's is refused.
        let mut lying = against_base;
        lying[1] = 9;
        assert!(decode_frame(&lying, &base).is_err());
    }

    #[test]
    fn a_primed_compressor_shared_by_frames_on_one_base_encodes_as_a_fresh_one() {
        let base = TerminalScreen::from_bytes(24, 80, &b"some text on the base\r\n".repeat(10));
        let mut encoder = FrameEncoder::default();
        for n in 1..5_u8 {
            let target = TerminalScreen::from_bytes(
                24,
                80,
                &[b"some text on the base\r\n".repeat(10), vec![b'a' + n]].concat(),
            );
            let frame = Frame {
                num: FrameNum(10 + u64::from(n)),
                base: FrameNum(9),
                echo_ack: InputSeq(0),
                diff: target.diff_from(&base),
            };
            let shared = encoder.encode(&frame, &base).unwrap();
            assert_eq!(shared, encode_frame(&frame, &base).unwrap());
            assert_eq!(decode_frame(&shared, &base).unwrap(), frame);
        }
    }

    #[test]
    fn truncated_and_corrupt_frames_are_errors() {
        let base = TerminalScreen::default();
        let bytes = encode_frame(&frame(), &base).unwrap();
        for cut in 0..bytes.len() {
            assert!(decode_frame(&bytes[..cut], &base).is_err(), "cut at {cut}");
        }
        assert!(decode_frame(b"not deflate at all", &base).is_err());
        assert!(decode_frame(b"\x07unknown", &base).is_err());
    }

    #[test]
    fn a_frame_naming_a_row_twice_or_out_of_order_is_refused() {
        // `[5; 1000]` would have the dictionary repeat one row a thousand times.
        for rows in [vec![5_u16; 1000], vec![5, 5], vec![6, 5]] {
            let mut bytes = postcard::to_extend(&9_u64, vec![TAG_FRAME]).unwrap();
            bytes = postcard::to_extend(&rows, bytes).unwrap();
            assert!(
                matches!(decode_server(&bytes), Err(ProtoError::Unordered)),
                "{rows:?}"
            );
        }
    }

    #[test]
    fn an_inflate_bomb_is_rejected() {
        // 64 MiB of zeros deflates to a few KiB; inflating it must stop at the cap.
        let bomb = miniz_oxide::deflate::compress_to_vec(&vec![0u8; 4 * MAX_FRAME], 9);
        assert!(bomb.len() < MAX_FRAME);
        let mut stream = vec![TAG_FRAME, 0, 0];
        stream.extend_from_slice(&bomb);
        assert!(matches!(
            decode_frame(&stream, &TerminalScreen::default()),
            Err(ProtoError::Inflate)
        ));
        // History inflates no further than the largest legal reply.
        let past = miniz_oxide::deflate::compress_to_vec(&vec![0u8; MAX_HISTORY_REPLY + 1], 9);
        assert!(matches!(decode_history(&past), Err(ProtoError::Inflate)));
    }
}
