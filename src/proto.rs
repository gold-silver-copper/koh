//! The koh/11 shell protocol: what a session's connection carries after its opening request
//! ([`crate::request`]).
//!
//! The client writes [`ClientMsg`]s on two uni streams, its first (the request's) for control
//! and one for input, each a 4-byte big-endian length followed by its postcard encoding. After
//! the [`Attached`](crate::request::Attached) that admits the client, the server sends what the
//! program shows on a uni stream, as [`Shown`] messages framed the same way: its output as it
//! wrote it (less what [`crate::stream`] takes out), the shell's marks, the state reports, and
//! what the predictor needs. Each stream is an epoch: it opens with a redraw of the screen, and a
//! client that fell too far behind is sent a new one, the old reset, so it never waits through a
//! backlog. A refusal, as any close, says why by its code ([`Close`]).
//!
//! Everything here is pure: the connection loops move bytes, this module turns them into messages
//! and rejects anything oversized or malformed.

use std::time::Duration;

use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};

use crate::bounded::at_most;
use crate::events::{check_events, InputEvent, WireColours};
use crate::terminal::{Activity, Size, TtyModes};

/// An input sequence number: which [`ClientMsg::Keys`] on this connection. The first is 1; 0
/// means "no input yet".
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct InputSeq(pub u64);

impl InputSeq {
    /// The sequence number after this one (saturating).
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

/// Most bytes in one encoded [`Shown`]: a piece of output and its framing.
pub const MAX_SHOWN: usize = crate::stream::MAX_OUT + 1024;

/// The server sends something at least this often, even when nothing changed, so the client can
/// tell a quiet session from a dead link.
pub const HEARTBEAT: Duration = Duration::from_secs(3);

/// The first byte of the server's stream of what a program shows; its epoch follows, 4 bytes
/// big-endian.
pub const SHOWN_TAG: u8 = 0x5e;

/// Why a connection was closed: its QUIC application close code.
///
/// The code is the only part read; the reason bytes a peer chooses are never shown, only
/// [`Close::text`]. Code 0 is none of these: an endpoint closing (a server restarting) uses it.
/// `NotAuthorized`, `NoSuchSession` and `OutOfScope` are for good: a shell's client redials after
/// the others but `SessionEnded`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Close {
    NotAuthorized = 1,
    /// The peer broke the protocol, or made no request in time.
    ProtocolError = 2,
    /// The hosted program exited, and the client was sent its end.
    SessionEnded = 3,
    /// The server holds its most sessions, and the client asked for a new one; or the session
    /// has as many attaches waiting as it takes.
    AtCapacity = 4,
    /// The session's program, or the command asked for, could not start, or the server is
    /// shutting down.
    CouldNotStart = 5,
    /// The session asked for by number is not the client's, or is gone.
    NoSuchSession = 6,
    /// The client's key is scoped to commands or copies, and asked for something else.
    OutOfScope = 7,
    /// The server has `--max-connections` connections, and as many waiting for one: nothing was
    /// done, and a retry may get in.
    Busy = 8,
    /// The directory a new session was to start in is not there, or is not a directory.
    NoSuchDir = 9,
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
            7 => Self::OutOfScope,
            8 => Self::Busy,
            9 => Self::NoSuchDir,
            _ => return None,
        })
    }

    /// What it says, for a person.
    pub const fn text(self) -> &'static str {
        match self {
            Self::NotAuthorized => "not authorized (is this client on the server's allowlist?)",
            Self::ProtocolError => "protocol error",
            Self::SessionEnded => "session ended",
            Self::AtCapacity => "the server holds its most sessions (`koh serve --max-sessions`)",
            Self::CouldNotStart => "the server could not start the program",
            Self::NoSuchSession => "no such session (it ended, or the server restarted)",
            Self::OutOfScope => {
                "this client's key is scoped on the server (`koh clients` there), and may not do \
                 that"
            }
            Self::Busy => "server busy: too many connections at once; retry",
            Self::NoSuchDir => crate::request::ProblemKind::NoSuchDir.text(),
        }
    }
}

impl std::fmt::Display for Close {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.text())
    }
}

impl std::error::Error for Close {}

/// A message on the client's stream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientMsg {
    /// The client's window is now `size`: its `n`th resize on the connection. It goes on both
    /// streams: on the control one, to wait for no input, and among the input, so nothing typed
    /// after it overtakes it. The server applies each `n` once, and none older than one applied.
    Resize { n: u32, size: Size },
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
    /// The client has read this many bytes of epoch `epoch`'s stream: the server keeps no more
    /// than the link carries in flight past it.
    Read { epoch: u32, bytes: u64 },
    /// The user's terminal lost what it showed (the client was suspended, its terminal used
    /// meanwhile): a new epoch, redrawn.
    Redraw,
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
            Self::Read { .. } | Self::Redraw => Stream::Control,
        }
    }

    /// Refuse input no terminal sends, which neither end sends nor takes.
    fn check(&self) -> Result<(), ProtoError> {
        match self {
            Self::Keys { events, .. } => check_events(events),
            Self::Colours(colours) => colours.check(),
            Self::Resize { .. } | Self::Read { .. } | Self::Redraw => Ok(()),
        }
        .map_err(ProtoError::BadInput)
    }
}

/// What the program shows, on the server's stream, in order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Shown {
    /// Output for the user's terminal.
    Out(#[serde(deserialize_with = "at_most::<{ crate::stream::MAX_OUT }, _, _>")] Vec<u8>),
    /// A shell mark, for the client to write with its terminal's nonce ([`MarkText`]).
    Mark(MarkText),
    /// What the program in the foreground is doing, newly probed, after the input up to `input`
    /// (this connection's) was written to it: a client that has sent more since holds it, as the
    /// program may not have had those keys yet.
    Report { activity: Activity, input: InputSeq },
    /// How the program's PTY takes typed keys: before the output they apply to.
    Tty(TtyModes),
    /// The input up to this one (this connection's) had its time to show: what the program
    /// echoed of it came before.
    Echo(InputSeq),
    /// The bell has rung this many times in the session's life: a rise is a ring.
    Bell(u64),
    /// The window title is now this, at most 256 characters.
    Title(#[serde(deserialize_with = "title")] String),
    /// The program exited, with this status; the session ends.
    Exit(u32),
    /// Nothing: the link lives.
    Beat,
}

fn title<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    let bytes = at_most::<{ crate::terminal::MAX_DIM as usize * 4 }, D, u8>(deserializer)?;
    let title = String::from_utf8(bytes).map_err(de::Error::custom)?;
    Ok(title
        .chars()
        .filter(|c| !c.is_control())
        .take(256)
        .collect())
}

/// A shell mark as `OSC 133 ;` would carry it: printable ASCII, at most
/// [`MAX_MARK`](crate::stream::MAX_MARK) bytes, no nonce, never a state report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MarkText(Vec<u8>);

impl MarkText {
    pub fn new(bytes: Vec<u8>) -> Option<Self> {
        let printable = bytes.iter().all(|b| (0x20..0x7f).contains(b));
        let nonce = bytes
            .split(|&b| b == b';')
            .any(|field| field.starts_with(b"nonce="));
        (!bytes.is_empty()
            && bytes.len() <= crate::stream::MAX_MARK
            && printable
            && !nonce
            && bytes.first() != Some(&b'S'))
        .then_some(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for MarkText {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = at_most::<{ crate::stream::MAX_MARK }, D, u8>(deserializer)?;
        Self::new(bytes).ok_or_else(|| de::Error::custom("a mark no terminal reads"))
    }
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
    #[error("a server stream of an unknown kind")]
    UnknownStream,
    #[error("input no terminal sends: {0}")]
    BadInput(&'static str),
}

/// Refuse `len` past `max` as [`ProtoError::TooLarge`].
fn at_most_len(len: usize, max: usize) -> Result<(), ProtoError> {
    (len <= max)
        .then_some(())
        .ok_or(ProtoError::TooLarge { len, max })
}

/// Encode one client message with its length prefix.
pub fn encode_client(msg: &ClientMsg) -> Result<Vec<u8>, ProtoError> {
    msg.check()?;
    crate::request::encode(msg, MAX_CLIENT_MESSAGE)
}

/// Encode what a program shows with its length prefix.
pub fn encode_shown(msg: &Shown) -> Result<Vec<u8>, ProtoError> {
    crate::request::encode(msg, MAX_SHOWN)
}

/// Splits a stream of length-prefixed messages back into them, however its bytes arrive, each
/// at most `MAX` bytes.
#[derive(Debug, Default)]
pub struct Decoder<const MAX: usize> {
    buf: Vec<u8>,
    /// How many bytes at the front of `buf` were already decoded. They are dropped in one move
    /// once no complete message is left, not after every message: one read can hold thousands.
    start: usize,
}

/// The client's messages, as the server reads them.
pub type ClientDecoder = Decoder<MAX_CLIENT_MESSAGE>;

/// What a program shows, as the client reads it.
pub type ShownDecoder = Decoder<MAX_SHOWN>;

impl<const MAX: usize> Decoder<MAX> {
    /// Append bytes read from the stream.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// The bytes not decoded yet.
    fn pending(&self) -> &[u8] {
        self.buf.get(self.start..).unwrap_or_default()
    }

    /// The next complete message's body, or `None` if more bytes are needed. An error means the
    /// peer broke the protocol; the caller closes the connection.
    fn next_body(&mut self) -> Result<Option<&[u8]>, ProtoError> {
        let Some((len, rest)) = self.pending().split_first_chunk::<4>() else {
            self.compact();
            return Ok(None);
        };
        let len = usize::try_from(u32::from_be_bytes(*len)).unwrap_or(usize::MAX);
        at_most_len(len, MAX)?;
        if rest.len() < len {
            self.compact();
            return Ok(None);
        }
        let from = self.start.saturating_add(4);
        let to = from.saturating_add(len);
        self.start = to.min(self.buf.len());
        Ok(self.buf.get(from..to))
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

impl ClientDecoder {
    /// The next complete client message, or `None` if more bytes are needed.
    pub fn next_msg(&mut self) -> Result<Option<ClientMsg>, ProtoError> {
        let Some(body) = self.next_body()? else {
            return Ok(None);
        };
        let msg: ClientMsg = postcard::from_bytes(body)?;
        msg.check()?;
        Ok(Some(msg))
    }
}

impl ShownDecoder {
    /// The next complete message of what the program shows, or `None` if more bytes are needed.
    pub fn next_shown(&mut self) -> Result<Option<Shown>, ProtoError> {
        let Some(body) = self.next_body()? else {
            return Ok(None);
        };
        Ok(Some(postcard::from_bytes(body)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A close says why by its code alone, each code one reason; 0, an endpoint closing, is none.
    #[test]
    fn close_codes_round_trip_and_0_is_none_of_them() {
        let all = [
            Close::NotAuthorized,
            Close::ProtocolError,
            Close::SessionEnded,
            Close::AtCapacity,
            Close::CouldNotStart,
            Close::NoSuchSession,
            Close::OutOfScope,
            Close::Busy,
            Close::NoSuchDir,
        ];
        for close in all {
            assert_eq!(Close::from_code(u64::from(close.code())), Some(close));
            assert!(close.text().is_ascii() && !close.text().contains('\n'));
        }
        assert_eq!(Close::from_code(0), None);
        assert_eq!(Close::from_code(10), None);
    }

    #[test]
    fn messages_decode_however_they_are_split_and_oversized_ones_are_refused() {
        let msgs = [
            Shown::Out(b"hello\x1b[1m".to_vec()),
            Shown::Mark(MarkText::new(b"D;1".to_vec()).unwrap()),
            Shown::Report {
                activity: Activity::Reading,
                input: InputSeq(4),
            },
            Shown::Echo(InputSeq(9)),
            Shown::Exit(3),
        ];
        let bytes: Vec<u8> = msgs.iter().flat_map(|m| encode_shown(m).unwrap()).collect();
        let mut decoder = ShownDecoder::default();
        let mut got = Vec::new();
        for byte in bytes.chunks(1) {
            decoder.push(byte);
            while let Some(msg) = decoder.next_shown().unwrap() {
                got.push(msg);
            }
        }
        assert_eq!(got, msgs);
        decoder.finish().unwrap();
        // A length past the bound is refused before its body comes.
        let mut decoder = ShownDecoder::default();
        decoder.push(&u32::MAX.to_be_bytes());
        assert!(decoder.next_shown().is_err());
        // A mark with a nonce, a control or a state report is not one.
        for bad in [&b"D;0;nonce=x"[..], b"A\x07", b"S;activity=busy", b""] {
            assert!(MarkText::new(bad.to_vec()).is_none(), "{bad:?}");
            let raw = crate::request::encode(&(1_u32, bad.to_vec()), usize::MAX).unwrap();
            let mut decoder = ShownDecoder::default();
            decoder.push(&raw);
            assert!(decoder.next_shown().is_err(), "{bad:?}");
        }
    }
}
