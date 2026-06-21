//! # rmosh-terminal — the `TerminalScreen` SSP state
//!
//! The server→client half of the synchronized world: the terminal *screen*, not a byte
//! stream. The server parses the shell's escape-sequence output into a 2-D cell grid; the
//! protocol's job is to bring the client to the server's *current* screen, collapsing any
//! intermediate frames. A port of mosh's `Terminal::Complete`, backed by the `vt100` crate.
//!
//! ## Why a snapshot, not a live parser
//!
//! `vt100::Parser` is **not** `Clone`, but the SSP transport stores cloned state snapshots.
//! So [`TerminalScreen`] holds an owned `vt100::Screen` (which *is* `Clone`). The server's
//! live, long-lived emulator lives in [`ServerTerminal`]; it produces a [`TerminalScreen`]
//! snapshot each tick. The client's [`TerminalScreen::apply`] reconstructs a throwaway parser
//! to replay the diff onto its baseline.
//!
//! ## The diff carries more than the grid
//!
//! `vt100::Screen::contents_diff` does not express resize or the echo-ack. So [`ScreenDiff`]
//! bundles three things, mirroring mosh's `HostMessage`: the optional `resize`, the
//! `echo_ack` (which the client's predictor consumes as the authoritative "your input up to
//! frame N is now on screen"), the optional window `title`, and the `vt` escape-sequence
//! patch (`state_diff`, or a full `state_formatted` repaint after a resize).

use rmosh_ssp::SyncState;
use serde::{Deserialize, Serialize};

mod server;

pub use server::ServerTerminal;

/// Default screen geometry, used for the initial (num 0) state both ends agree on.
pub const DEFAULT_ROWS: u16 = 24;
pub const DEFAULT_COLS: u16 = 80;
/// Server-side debounce before a received input frame is considered "echoed" (mosh `ECHO_TIMEOUT`).
pub const ECHO_TIMEOUT_MS: u64 = 50;

/// Build a blank `vt100::Screen` of the given size (the only way to get an owned `Screen`,
/// since `Screen::new` is `pub(crate)`).
fn blank_screen(rows: u16, cols: u16) -> vt100::Screen {
    vt100::Parser::new(rows, cols, 0).screen().clone()
}

/// The synchronized screen state.
///
/// Holds an owned `vt100::Screen` snapshot (what `diff_from`/`PartialEq`/render read, and what
/// survives `Clone` — `vt100::Parser` is not `Clone`), plus a live parser kept across `apply`
/// calls so incremental diffs are `O(diff)`, not a full re-parse of the whole grid per frame.
pub struct TerminalScreen {
    screen: vt100::Screen,
    /// Newest user-input frame number the server has echoed (drives the client predictor).
    echo_ack: u64,
    /// Window title (OSC 2), propagated so the client can mirror it.
    title: String,
    /// Long-lived parser, in sync with `screen` whenever `Some`. Not part of identity; dropped
    /// on `Clone` (Parser is not Clone) and lazily rebuilt from `screen` on the next `apply`.
    parser: Option<Box<vt100::Parser>>,
}

impl Clone for TerminalScreen {
    fn clone(&self) -> Self {
        // Drop the live parser on clone; the snapshot carries the state and the next apply
        // rebuilds the parser from it. Clone is the rare path (transport state snapshots), so a
        // later one-time rebuild is fine — the per-frame apply stays cheap.
        TerminalScreen {
            screen: self.screen.clone(),
            echo_ack: self.echo_ack,
            title: self.title.clone(),
            parser: None,
        }
    }
}

impl std::fmt::Debug for TerminalScreen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TerminalScreen")
            .field("size", &self.screen.size())
            .field("echo_ack", &self.echo_ack)
            .field("title", &self.title)
            .finish()
    }
}

impl Default for TerminalScreen {
    fn default() -> Self {
        TerminalScreen {
            screen: blank_screen(DEFAULT_ROWS, DEFAULT_COLS),
            echo_ack: 0,
            title: String::new(),
            parser: None,
        }
    }
}

impl TerminalScreen {
    /// Construct a screen by feeding `bytes` of terminal output into a fresh emulator of the
    /// given size (useful for tests and for the client's initial baseline).
    pub fn from_bytes(rows: u16, cols: u16, bytes: &[u8]) -> Self {
        let mut p = vt100::Parser::new(rows, cols, 0);
        p.process(bytes);
        TerminalScreen {
            screen: p.screen().clone(),
            echo_ack: 0,
            title: String::new(),
            parser: None,
        }
    }

    /// Borrow the underlying `vt100::Screen` (for rendering and predictor reconciliation).
    pub fn screen(&self) -> &vt100::Screen {
        &self.screen
    }

    /// `(rows, cols)`.
    pub fn size(&self) -> (u16, u16) {
        self.screen.size()
    }

    /// The server's echo-ack: the newest input frame number reflected on this screen.
    pub fn echo_ack(&self) -> u64 {
        self.echo_ack
    }

    /// The window title, if the server has set one.
    pub fn title(&self) -> &str {
        &self.title
    }
}

/// The wire delta between two [`TerminalScreen`]s (mosh `HostMessage`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScreenDiff {
    /// New `(rows, cols)` if the screen was resized; when set, `vt` is a full repaint.
    pub resize: Option<(u16, u16)>,
    /// The server's echo-ack at the target state.
    pub echo_ack: u64,
    /// New window title if it changed.
    pub title: Option<String>,
    /// The `vt100` escape-sequence patch: `state_diff(base)` normally, or `state_formatted`
    /// (a self-contained repaint) when `resize` is set.
    pub vt: Vec<u8>,
}

impl SyncState for TerminalScreen {
    type Diff = ScreenDiff;

    fn diff_from(&self, base: &Self) -> Self::Diff {
        let resized = self.size() != base.size();
        let vt = if resized {
            // After a resize, vt100 does not reflow; ship a self-contained repaint.
            self.screen.state_formatted()
        } else {
            self.screen.state_diff(&base.screen)
        };
        ScreenDiff {
            resize: resized.then(|| self.size()),
            echo_ack: self.echo_ack,
            title: (self.title != base.title).then(|| self.title.clone()),
            vt,
        }
    }

    fn apply(&mut self, diff: &Self::Diff) {
        if let Some((rows, cols)) = diff.resize {
            // Resize: vt100 doesn't reflow, so `vt` is a self-contained repaint at the new size.
            // Rebuild the parser at the new geometry (rare path) and replay the repaint.
            let mut p = Box::new(vt100::Parser::new(rows, cols, 0));
            p.process(&diff.vt);
            self.screen = p.screen().clone();
            self.parser = Some(p);
        } else {
            // Lazily (re)build the parser from the snapshot on the first apply / after a clone,
            // then feed only the incremental diff bytes. Steady-state cost is O(diff.vt), not a
            // full re-parse of the whole grid every frame.
            let parser = self.parser.get_or_insert_with(|| {
                let (rows, cols) = self.screen.size();
                let mut p = Box::new(vt100::Parser::new(rows, cols, 0));
                p.process(&self.screen.state_formatted());
                p
            });
            if !diff.vt.is_empty() {
                parser.process(&diff.vt);
            }
            // Keep the snapshot in sync for PartialEq / diff_from / render.
            self.screen = parser.screen().clone();
        }
        self.echo_ack = self.echo_ack.max(diff.echo_ack);
        if let Some(title) = &diff.title {
            self.title = title.clone();
        }
    }

    // subtract_prefix: screen state is absolute, so the default no-op is correct (mosh's
    // `Complete::subtract` is likewise a no-op).
}

impl PartialEq for TerminalScreen {
    fn eq(&self, other: &Self) -> bool {
        self.echo_ack == other.echo_ack
            && self.title == other.title
            && self.screen.size() == other.screen.size()
            // Two screens are equal for collapse purposes iff they render identically
            // (contents + cursor + input modes), i.e. their state_diff is empty.
            && self.screen.state_diff(&other.screen).is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmosh_ssp::testkit::{LinkParams, SimHarness};

    fn screen_from(rows: u16, cols: u16, bytes: &[u8]) -> TerminalScreen {
        TerminalScreen::from_bytes(rows, cols, bytes)
    }

    #[test]
    fn diff_apply_roundtrip_simple() {
        let base = TerminalScreen::default();
        let target = screen_from(24, 80, b"hello \x1b[31mworld\x1b[m");
        let diff = target.diff_from(&base);
        let mut c = base.clone();
        c.apply(&diff);
        assert_eq!(c, target);
    }

    #[test]
    fn diff_apply_roundtrip_incremental() {
        let a = screen_from(24, 80, b"line one\r\nline two");
        let b = screen_from(24, 80, b"line one\r\nline two\r\nline three\x1b[1;1Hedited");
        let diff = b.diff_from(&a);
        assert!(!diff.vt.is_empty());
        assert!(diff.resize.is_none());
        let mut c = a.clone();
        c.apply(&diff);
        assert_eq!(c, b);
    }

    #[test]
    fn resize_roundtrip_full_repaint() {
        let a = screen_from(24, 80, b"small screen content here");
        let b = screen_from(40, 120, b"now a much wider and taller screen\r\nwith two lines");
        let diff = b.diff_from(&a);
        assert_eq!(diff.resize, Some((40, 120)));
        let mut c = a.clone();
        c.apply(&diff);
        assert_eq!(c, b);
        assert_eq!(c.size(), (40, 120));
    }

    #[test]
    fn equal_screens_compare_equal() {
        let a = screen_from(24, 80, b"identical");
        let b = screen_from(24, 80, b"identical");
        assert_eq!(a, b);
        assert!(a.diff_from(&b).vt.is_empty());
    }

    #[test]
    fn wide_chars_and_emoji_roundtrip() {
        // CJK (wide) + emoji + combining marks must survive diff/apply.
        let base = TerminalScreen::default();
        let target = screen_from(24, 80, "日本語 café 🦀 e\u{0301}".as_bytes());
        let diff = target.diff_from(&base);
        let mut c = base.clone();
        c.apply(&diff);
        assert_eq!(c, target);
    }

    #[test]
    fn converges_over_lossy_link() {
        // Server (A) evolves its screen; client (B) must converge to the latest frame.
        let mut h = SimHarness::<TerminalScreen, TerminalScreen>::new(LinkParams::lossy(), 77, 1200);
        let mut emu = ServerTerminal::new(24, 80, 0);
        for i in 0..30u32 {
            emu.process(format!("\r\nframe {i} of output").as_bytes());
            *h.a_mut() = emu.snapshot();
            h.run_steps(5);
        }
        let final_snap = emu.snapshot();
        h.run_until(20_000, move |h| *h.b_view_of_a() == final_snap);
    }

    #[test]
    fn many_incremental_applies_without_reclone_track_server() {
        // The client holds ONE TerminalScreen and applies a long run of incremental diffs,
        // exercising the persistent-parser path (the parser is built once on the first apply and
        // reused — never rebuilt per frame). It must track the server's snapshot exactly.
        let mut emu = ServerTerminal::new(24, 80, 0);
        emu.process(b"line 0\r\n");
        let mut client = emu.snapshot();
        let mut base = client.clone();

        for i in 1..=20 {
            emu.process(format!("line {i}\r\n").as_bytes());
            let target = emu.snapshot();
            let diff = target.diff_from(&base);
            assert!(diff.resize.is_none(), "no resize -> incremental (persistent) path");
            client.apply(&diff); // same object, repeated apply (no clone between frames)
            base = target.clone();
            assert_eq!(client, base, "client must track server after incremental diff {i}");
        }
    }
}
