//! The koh/3 wire protocol.
//!
//! After admission the client opens one uni stream and writes [`ClientMsg`]s on it, each a 4-byte
//! big-endian length followed by its postcard encoding. The server sends every screen update as a
//! [`Frame`] on its own uni stream: the DEFLATE-compressed postcard encoding, and nothing else.
//! Frames diff against a frame the client has acknowledged, so a lost or reset frame only delays
//! the screen until the next one.
//!
//! Everything here is pure: the connection loops move bytes, this module turns them into messages
//! and rejects anything oversized or malformed.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::terminal::ScreenDiff;

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

/// An input sequence number: which [`ClientMsg::Input`] on this connection. The first is 1; 0
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

/// Most typed bytes in one [`ClientMsg::Input`]; the client splits a paste into several.
pub const MAX_INPUT_BYTES: usize = 64 * 1024;

/// Most bytes in one encoded client message: the largest `Input` plus room for its envelope.
pub const MAX_CLIENT_MESSAGE: usize = MAX_INPUT_BYTES + 64;

/// Most bytes in a frame, both compressed on the stream and inflated. A full repaint of a
/// 1000×1000 screen with varied styles is several MiB.
pub const MAX_FRAME: usize = 16 * 1024 * 1024;

/// How many recent screens each end keeps.
///
/// The client keeps its last applied frames, the server the frames it sent since the newest one
/// acknowledged. A constant, so neither end's memory grows with what the peer sends or withholds.
pub const FRAME_WINDOW: usize = 16;

/// The server sends a frame at least this often, even when nothing changed, so the client can tell
/// a quiet session from a dead link.
pub const HEARTBEAT: Duration = Duration::from_secs(3);

/// The reason, with close code 0, the server closes a connection with once the hosted program
/// exited and the client has the final frame.
pub const SESSION_ENDED: &[u8] = b"session ended";

/// The shortest and longest gap the server leaves between frames.
const MIN_FRAME_INTERVAL: Duration = Duration::from_millis(20);
const MAX_FRAME_INTERVAL: Duration = Duration::from_millis(250);

/// The RTT assumed before the path has measured one (QUIC's initial RTT).
const INITIAL_RTT: Duration = Duration::from_millis(333);

/// How long an unacknowledged frame, or unconfirmed input, waits before the sender acts on its own.
///
/// A round trip plus a frame interval. The server then resends its newest screen as a new frame,
/// and the client sends a probe, instead of waiting out QUIC's exponentially backed-off probe
/// timeout, which on a lossy, jittery path is several round trips.
pub fn retry_after(rtt: Option<Duration>) -> Duration {
    rtt.unwrap_or(INITIAL_RTT)
        .saturating_add(frame_interval(rtt))
}

/// The gap the server leaves between frames on a path with round-trip time `rtt`: two frames per
/// round trip, within `[20 ms, 250 ms]`. An unknown RTT gets the longest gap.
pub fn frame_interval(rtt: Option<Duration>) -> Duration {
    rtt.map_or(MAX_FRAME_INTERVAL, |rtt| {
        // `Duration / u32` panics only on a zero divisor.
        rtt.checked_div(2)
            .unwrap_or(MAX_FRAME_INTERVAL)
            .clamp(MIN_FRAME_INTERVAL, MAX_FRAME_INTERVAL)
    })
}

/// DEFLATE level for frames. Screen diffs are very compressible (runs of spaces, repeated
/// styles), so a mid level gets most of the ratio at little CPU.
const COMPRESSION_LEVEL: u8 = 6;

/// A message on the client's stream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientMsg {
    /// Typed bytes, at most [`MAX_INPUT_BYTES`].
    Input { seq: InputSeq, bytes: Vec<u8> },
    /// The client's window is now `rows × cols`.
    Resize { rows: u16, cols: u16 },
    /// The client applied `frame`; later frames may diff against it.
    Ack { frame: FrameNum },
    /// The client got a frame whose base it does not hold; the next frame must diff against
    /// [`FrameNum::BLANK`].
    Resync,
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
    #[error("input of {len} bytes exceeds the {max}-byte limit")]
    InputTooLarge { len: usize, max: usize },
    #[error("stream ended inside a message")]
    Truncated,
    #[error("malformed message: {0}")]
    Malformed(#[from] postcard::Error),
    #[error("could not inflate the frame (corrupt, or larger than {MAX_FRAME} bytes)")]
    Inflate,
}

/// Encode one client message with its length prefix.
pub fn encode_client(msg: &ClientMsg) -> Result<Vec<u8>, ProtoError> {
    if let ClientMsg::Input { bytes, .. } = msg {
        if bytes.len() > MAX_INPUT_BYTES {
            return Err(ProtoError::InputTooLarge {
                len: bytes.len(),
                max: MAX_INPUT_BYTES,
            });
        }
    }
    let body = postcard::to_allocvec(msg)?;
    let Ok(len) = u32::try_from(body.len()) else {
        return Err(ProtoError::TooLarge {
            len: body.len(),
            max: MAX_CLIENT_MESSAGE,
        });
    };
    Ok([len.to_be_bytes().as_slice(), &body].concat())
}

/// Splits the client's stream back into messages, however its bytes arrive.
#[derive(Debug, Default)]
pub struct ClientDecoder {
    buf: Vec<u8>,
}

impl ClientDecoder {
    /// Append bytes read from the stream.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// The next complete message, or `None` if more bytes are needed. An error means the peer
    /// broke the protocol; the caller closes the connection.
    pub fn next_msg(&mut self) -> Result<Option<ClientMsg>, ProtoError> {
        let Some((len, rest)) = self.buf.split_first_chunk::<4>() else {
            return Ok(None);
        };
        let len = usize::try_from(u32::from_be_bytes(*len)).unwrap_or(usize::MAX);
        if len > MAX_CLIENT_MESSAGE {
            return Err(ProtoError::TooLarge {
                len,
                max: MAX_CLIENT_MESSAGE,
            });
        }
        let Some(body) = rest.get(..len) else {
            return Ok(None);
        };
        let msg: ClientMsg = postcard::from_bytes(body)?;
        if let ClientMsg::Input { bytes, .. } = &msg {
            if bytes.len() > MAX_INPUT_BYTES {
                return Err(ProtoError::InputTooLarge {
                    len: bytes.len(),
                    max: MAX_INPUT_BYTES,
                });
            }
        }
        // The header and body were just read, so `4 + len` is within the buffer.
        let consumed = len.saturating_add(4).min(self.buf.len());
        self.buf.drain(..consumed);
        Ok(Some(msg))
    }

    /// The stream ended: fine between messages, a protocol error inside one.
    pub fn finish(&self) -> Result<(), ProtoError> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(ProtoError::Truncated)
        }
    }
}

/// Encode a frame for its stream.
pub fn encode_frame(frame: &Frame) -> Result<Vec<u8>, ProtoError> {
    let raw = postcard::to_allocvec(frame)?;
    Ok(miniz_oxide::deflate::compress_to_vec(
        &raw,
        COMPRESSION_LEVEL,
    ))
}

/// Decode a frame's stream contents, inflating at most [`MAX_FRAME`] bytes.
#[expect(
    clippy::map_err_ignore,
    reason = "miniz's error carries the partial, attacker-controlled inflate output; \
              `ProtoError::Inflate` deliberately reports only corrupt-or-oversized"
)]
pub fn decode_frame(bytes: &[u8]) -> Result<Frame, ProtoError> {
    if bytes.len() > MAX_FRAME {
        return Err(ProtoError::TooLarge {
            len: bytes.len(),
            max: MAX_FRAME,
        });
    }
    let raw = miniz_oxide::inflate::decompress_to_vec_with_limit(bytes, MAX_FRAME)
        .map_err(|_| ProtoError::Inflate)?;
    Ok(postcard::from_bytes(&raw)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::terminal::TerminalScreen;

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
            ClientMsg::Input {
                seq: InputSeq(1),
                bytes: b"ls -la\r".to_vec(),
            },
            ClientMsg::Resize {
                rows: 50,
                cols: 132,
            },
            ClientMsg::Ack { frame: FrameNum(9) },
            ClientMsg::Resync,
            ClientMsg::Input {
                seq: InputSeq(2),
                bytes: vec![0x1b; MAX_INPUT_BYTES],
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
    fn oversized_client_messages_are_rejected_before_buffering() {
        let too_long = ClientMsg::Input {
            seq: InputSeq(1),
            bytes: vec![b'a'; MAX_INPUT_BYTES + 1],
        };
        assert!(matches!(
            encode_client(&too_long),
            Err(ProtoError::InputTooLarge { .. })
        ));
        // A header announcing more than the cap is refused as soon as the header arrives.
        let mut decoder = ClientDecoder::default();
        let len = u32::try_from(MAX_CLIENT_MESSAGE + 1).unwrap();
        decoder.push(&len.to_be_bytes());
        assert!(matches!(
            decoder.next_msg(),
            Err(ProtoError::TooLarge { .. })
        ));
        // A hand-built Input over the byte cap, inside a legal envelope, is refused too.
        let body = postcard::to_allocvec(&ClientMsg::Input {
            seq: InputSeq(1),
            bytes: vec![b'a'; MAX_INPUT_BYTES + 10],
        })
        .unwrap();
        let mut stream = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
        stream.extend_from_slice(&body);
        assert!(matches!(
            decode_all(&stream),
            Err(ProtoError::InputTooLarge { .. } | ProtoError::TooLarge { .. })
        ));
    }

    #[test]
    fn truncated_and_garbage_client_streams_are_errors() {
        let stream = encode_client(&ClientMsg::Resize { rows: 1, cols: 2 }).unwrap();
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
    fn frames_round_trip() {
        let frame = frame();
        assert_eq!(decode_frame(&encode_frame(&frame).unwrap()).unwrap(), frame);
    }

    #[test]
    fn truncated_and_corrupt_frames_are_errors() {
        let bytes = encode_frame(&frame()).unwrap();
        for cut in 0..bytes.len() {
            assert!(decode_frame(&bytes[..cut]).is_err(), "cut at {cut}");
        }
        assert!(decode_frame(b"not deflate at all").is_err());
    }

    #[test]
    fn an_inflate_bomb_is_rejected() {
        // 64 MiB of zeros deflates to a few KiB; inflating it must stop at the cap.
        let bomb = miniz_oxide::deflate::compress_to_vec(&vec![0u8; 4 * MAX_FRAME], 9);
        assert!(bomb.len() < MAX_FRAME);
        assert!(matches!(decode_frame(&bomb), Err(ProtoError::Inflate)));
    }

    #[test]
    fn frames_go_out_twice_per_round_trip_within_bounds() {
        let ms = Duration::from_millis;
        assert_eq!(frame_interval(None), ms(250));
        assert_eq!(frame_interval(Some(ms(2))), ms(20));
        assert_eq!(frame_interval(Some(ms(100))), ms(50));
        assert_eq!(frame_interval(Some(ms(2000))), ms(250));
    }

    #[test]
    fn a_retry_waits_a_round_trip_and_a_frame_interval() {
        let ms = Duration::from_millis;
        assert_eq!(retry_after(Some(ms(200))), ms(300));
        assert_eq!(retry_after(Some(ms(10))), ms(30));
        assert_eq!(retry_after(None), ms(333 + 250));
    }

    #[test]
    fn frame_and_sequence_numbers_saturate() {
        assert_eq!(FrameNum(u64::MAX).next(), FrameNum(u64::MAX));
        assert_eq!(InputSeq(u64::MAX).next(), InputSeq(u64::MAX));
        assert_eq!(FrameNum::BLANK.next(), FrameNum(1));
    }
}
