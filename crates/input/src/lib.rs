//! # koh-input — the `UserInput` SSP state
//!
//! The client→server half of the synchronized world: the user's keystrokes and window-size
//! changes, modeled as an ordered, append-only log so it flows through the SSP just like the
//! screen does (diff'd, sequenced, acked) and is therefore never lost or duplicated across
//! drops. A direct port of mosh's `Network::UserStream`.
//!
//! ## Storage vs. wire
//!
//! Internally the log is *per-byte* ([`InputEvent::Byte`]) so an already-acked prefix is a
//! clean prefix of the current state — that is what makes [`SyncState::diff_from`] and
//! [`SyncState::subtract_prefix`] correct as simple range operations. On the wire, the diff
//! coalesces consecutive bytes into [`WireEvent::Keys`] blobs (mosh's `keystroke` packing),
//! so a typed run costs one length-prefixed blob, not one tag per byte.

use koh_ssp::SyncState;
use serde::{Deserialize, Serialize};

/// One stored input event. Keystrokes are stored a byte at a time so the log stays a clean
/// append-only sequence (resizes are interleaved in typing order and never coalesced).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum InputEvent {
    /// A single byte typed by the user (already in the terminal's input encoding).
    Byte(u8),
    /// The client window was resized to `rows`×`cols`; drives `SIGWINCH` on the server.
    Resize { rows: u16, cols: u16 },
}

/// One wire event: the compact, coalesced form of a diff (a typed run packs into `Keys`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireEvent {
    /// A coalesced run of typed bytes.
    Keys(Vec<u8>),
    /// A resize notification.
    Resize { rows: u16, cols: u16 },
}

/// The ordered keystroke/resize stream the client authors and the server applies.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UserInput {
    events: Vec<InputEvent>,
}

impl UserInput {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a single typed byte.
    pub fn push_byte(&mut self, b: u8) {
        self.events.push(InputEvent::Byte(b));
    }

    /// Append a run of typed bytes (e.g. a multi-byte key or pasted text).
    pub fn push_bytes(&mut self, bytes: &[u8]) {
        self.events
            .extend(bytes.iter().copied().map(InputEvent::Byte));
    }

    /// Append a window-resize event.
    pub fn push_resize(&mut self, rows: u16, cols: u16) {
        self.events.push(InputEvent::Resize { rows, cols });
    }

    /// The full stored event log.
    pub fn events(&self) -> &[InputEvent] {
        &self.events
    }

    /// Number of stored events.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

/// Coalesce a tail of stored events into compact wire events.
fn coalesce(tail: &[InputEvent]) -> Vec<WireEvent> {
    let mut out: Vec<WireEvent> = Vec::new();
    for e in tail {
        match e {
            InputEvent::Byte(b) => {
                if let Some(WireEvent::Keys(buf)) = out.last_mut() {
                    buf.push(*b);
                } else {
                    out.push(WireEvent::Keys(vec![*b]));
                }
            }
            InputEvent::Resize { rows, cols } => out.push(WireEvent::Resize {
                rows: *rows,
                cols: *cols,
            }),
        }
    }
    out
}

/// Length of the longest common prefix of two event logs.
///
/// For a well-behaved (append-only) peer the `base` always *is* a prefix of `self`, so this equals
/// `base.len()` — the historical `min(base.len, self.len)`. But peer input is untrusted: an
/// authorized-but-malicious peer can ship independent diffs from divergent bases that arrive
/// out-of-order, leaving `base` NOT a prefix of `self`. Computing the real common-prefix length
/// (instead of trusting `base.len()`) makes [`diff_from`](UserInput::diff_from) and
/// [`subtract_prefix`](UserInput::subtract_prefix) robust: no panic on peer input, and the
/// divergent tail is neither silently dropped (which would corrupt the synced stream) nor blindly
/// discarded.
fn common_prefix_len(a: &[InputEvent], b: &[InputEvent]) -> usize {
    a.iter().zip(b).take_while(|(x, y)| x == y).count()
}

impl SyncState for UserInput {
    type Diff = Vec<WireEvent>;

    fn diff_from(&self, base: &Self) -> Self::Diff {
        // `base` SHOULD be a prefix of `self` (the append-only invariant) and is for honest peers;
        // fall back to the real common prefix rather than `debug_assert!`-panicking on a divergent
        // base from untrusted peer input.
        let n = common_prefix_len(&self.events, &base.events);
        // `n` is a common-prefix length, so `n <= self.events.len()` always and `get(n..)` is
        // `Some`; the `unwrap_or_default` keeps this genuinely panic-free without an `indexing`.
        coalesce(self.events.get(n..).unwrap_or_default())
    }

    fn apply(&mut self, diff: &Self::Diff) {
        for w in diff {
            match w {
                WireEvent::Keys(bytes) => self.push_bytes(bytes),
                WireEvent::Resize { rows, cols } => self.push_resize(*rows, *cols),
            }
        }
    }

    fn subtract_prefix(&mut self, prefix: &Self) {
        // Drop only the genuinely-shared prefix; never drain past a divergence (which would
        // corrupt this state and, via `get_remote_diff`, poison the delivered-state baseline).
        let n = common_prefix_len(&self.events, &prefix.events);
        self.events.drain(0..n);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use koh_ssp::testkit::{LinkParams, SimHarness};

    #[test]
    fn diff_apply_roundtrip() {
        let mut base = UserInput::new();
        base.push_bytes(b"ls -la");
        let mut target = base.clone();
        target.push_resize(40, 120);
        target.push_bytes(b"\rcd /");

        let diff = target.diff_from(&base);
        let mut c = base.clone();
        c.apply(&diff);
        assert_eq!(c, target);
    }

    #[test]
    fn diff_coalesces_runs() {
        let mut ui = UserInput::new();
        ui.push_bytes(b"abc");
        ui.push_resize(10, 10);
        ui.push_bytes(b"de");
        let diff = ui.diff_from(&UserInput::new());
        assert_eq!(
            diff,
            vec![
                WireEvent::Keys(b"abc".to_vec()),
                WireEvent::Resize { rows: 10, cols: 10 },
                WireEvent::Keys(b"de".to_vec()),
            ]
        );
    }

    #[test]
    fn subtract_prefix_collapses() {
        let mut ui = UserInput::new();
        ui.push_bytes(b"hello");
        let mut acked = UserInput::new();
        acked.push_bytes(b"hel");
        ui.subtract_prefix(&acked);
        assert_eq!(
            ui.events(),
            &[InputEvent::Byte(b'l'), InputEvent::Byte(b'o')]
        );
    }

    #[test]
    fn diff_from_divergent_base_is_robust_and_keeps_the_tail() {
        // Untrusted peers can make `base` NOT a prefix of `self` (divergent diffs delivered
        // out-of-order). This must NOT panic (old debug_assert) and must NOT silently drop the
        // divergent tail (old min()-based code returned an empty diff, dropping real input).
        let mut target = UserInput::new();
        target.push_bytes(b"abd"); // [a, b, d]
        let mut base = UserInput::new();
        base.push_bytes(b"abc"); // [a, b, c] — diverges at index 2, same length
                                 // The diff is the tail after the genuine common prefix [a, b]: just 'd'.
        assert_eq!(
            target.diff_from(&base),
            vec![WireEvent::Keys(b"d".to_vec())]
        );
        // A prefix base still behaves exactly as before (the common path).
        let mut prefix = UserInput::new();
        prefix.push_bytes(b"ab");
        assert_eq!(
            target.diff_from(&prefix),
            vec![WireEvent::Keys(b"d".to_vec())]
        );
    }

    #[test]
    fn subtract_prefix_divergent_keeps_divergent_tail() {
        // A non-prefix argument must only drain the genuinely-shared prefix, never past the
        // divergence (which would corrupt the state and poison the delivered baseline).
        let mut s = UserInput::new();
        s.push_bytes(b"abd");
        let mut other = UserInput::new();
        other.push_bytes(b"abc");
        s.subtract_prefix(&other); // common prefix [a, b] (len 2) drained; 'd' kept
        assert_eq!(s.events(), &[InputEvent::Byte(b'd')]);
    }

    #[test]
    fn converges_over_lossy_link() {
        // Client (A) types; server (B) must reconstruct the exact stream despite chaos.
        let mut h = SimHarness::<UserInput, UserInput>::new(LinkParams::lossy(), 2024, 1200);
        let mut typed = UserInput::new();
        for round in 0..40u8 {
            h.a_mut().push_byte(b'a' + (round % 26));
            typed.push_byte(b'a' + (round % 26));
            if round % 7 == 0 {
                h.a_mut().push_resize(20 + u16::from(round), 80);
                typed.push_resize(20 + u16::from(round), 80);
            }
            h.run_steps(6);
        }
        let expected = typed.events().to_vec();
        h.run_until(20_000, move |h| {
            h.b_view_of_a().events() == expected.as_slice()
        });
    }

    #[test]
    fn server_drains_input_incrementally() {
        // Exercise Transport::get_remote_diff on the receiving (server) side.
        let mut h = SimHarness::<UserInput, UserInput>::new(LinkParams::perfect(), 5, 1200);
        let mut reconstructed: Vec<u8> = Vec::new();

        h.a_mut().push_bytes(b"echo hi"); // 7 events
        h.run_until(2000, |h| h.b_view_of_a().len() >= 7);
        for w in h.b.get_remote_diff() {
            if let WireEvent::Keys(b) = w {
                reconstructed.extend_from_slice(&b);
            }
        }
        assert_eq!(reconstructed, b"echo hi");

        h.a_mut().push_bytes(b"\rwhoami"); // +7 = 14 events total
        h.run_until(2000, |h| h.b_view_of_a().len() >= 14);
        for w in h.b.get_remote_diff() {
            if let WireEvent::Keys(b) = w {
                reconstructed.extend_from_slice(&b);
            }
        }
        assert_eq!(reconstructed, b"echo hi\rwhoami");
    }
}
