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
    /// Set once the remote shell has exited, carrying its exit code so the client can exit with
    /// the same status (mosh parity). `None` while the shell is alive.
    exit_code: Option<u32>,
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
            exit_code: self.exit_code,
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
            .field("exit_code", &self.exit_code)
            .finish()
    }
}

impl Default for TerminalScreen {
    fn default() -> Self {
        TerminalScreen {
            screen: blank_screen(DEFAULT_ROWS, DEFAULT_COLS),
            echo_ack: 0,
            title: String::new(),
            exit_code: None,
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
            exit_code: None,
            parser: None,
        }
    }

    /// Borrow the underlying `vt100::Screen` (for rendering and predictor reconciliation).
    pub fn screen(&self) -> &vt100::Screen {
        &self.screen
    }

    /// The remote shell's exit code, once it has exited (`None` while alive).
    pub fn exit_code(&self) -> Option<u32> {
        self.exit_code
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
    /// The remote shell's exit code, set on the final (shutdown) frame.
    pub exit_code: Option<u32>,
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
            exit_code: self.exit_code,
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
        if diff.exit_code.is_some() {
            self.exit_code = diff.exit_code;
        }
    }

    // subtract_prefix: screen state is absolute, so the default no-op is correct (mosh's
    // `Complete::subtract` is likewise a no-op).
}

impl PartialEq for TerminalScreen {
    fn eq(&self, other: &Self) -> bool {
        self.echo_ack == other.echo_ack
            && self.title == other.title
            // Include exit_code so the final "shell exited" state isn't collapsed as unchanged.
            && self.exit_code == other.exit_code
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
        let b = screen_from(
            40,
            120,
            b"now a much wider and taller screen\r\nwith two lines",
        );
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
        let mut h =
            SimHarness::<TerminalScreen, TerminalScreen>::new(LinkParams::lossy(), 77, 1200);
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
            assert!(
                diff.resize.is_none(),
                "no resize -> incremental (persistent) path"
            );
            client.apply(&diff); // same object, repeated apply (no clone between frames)
            base = target.clone();
            assert_eq!(
                client, base,
                "client must track server after incremental diff {i}"
            );
        }
    }

    #[test]
    fn exit_code_propagates_through_diff_apply() {
        // When the shell exits, the server stamps the code; it must survive diff -> apply, and a
        // state carrying an exit code must NOT compare equal to one without (so it isn't collapsed).
        let mut emu = ServerTerminal::new(24, 80, 0);
        emu.process(b"bye");
        emu.set_exit_code(42);
        let target = emu.snapshot();
        assert_eq!(target.exit_code(), Some(42));

        let base = TerminalScreen::default();
        let diff = target.diff_from(&base);
        assert_eq!(diff.exit_code, Some(42));

        let mut c = base.clone();
        c.apply(&diff);
        assert_eq!(c.exit_code(), Some(42));
        assert_ne!(
            base, c,
            "a state carrying an exit code differs from one without"
        );
    }

    // --- Ported mosh terminal-emulation / unicode regression tests, recast as SSP round-trip
    // tests: feed the byte sequence from the corresponding mosh test to the server emulator, ship
    // the snapshot through diff/apply onto a fresh client, and assert the client reconstructs the
    // screen EXACTLY (moshers2's verification guarantee) plus the semantic outcome mosh checked.
    // mosh source: src/tests/emulation-*.test, unicode-*.test. ---

    /// Process `bytes`, ship server→client via diff/apply, assert exact reconstruction, and
    /// return the reconstructed client screen for semantic assertions.
    fn roundtrip(rows: u16, cols: u16, bytes: &[u8]) -> TerminalScreen {
        let mut emu = ServerTerminal::new(rows, cols, 0);
        emu.process(bytes);
        let target = emu.snapshot();
        let base = TerminalScreen::default();
        let diff = target.diff_from(&base);
        let mut client = base.clone();
        client.apply(&diff);
        assert_eq!(
            client, target,
            "client must reconstruct the server screen exactly"
        );
        client
    }

    /// Trimmed text of one screen row (blank cells as spaces), for line-level assertions.
    fn row_text(s: &vt100::Screen, row: u16) -> String {
        let (_, cols) = s.size();
        (0..cols)
            .map(|c| match s.cell(row, c).map(|x| x.contents()) {
                Some(g) if !g.is_empty() => g.to_string(),
                _ => " ".to_string(),
            })
            .collect::<String>()
            .trim_end()
            .to_string()
    }

    #[test]
    fn attributes_survive_roundtrip() {
        // mosh emulation-attributes{,-16color,-256color8,-256color248,-truecolor}: SGR
        // attributes and colors must reconstruct on the client.
        let bytes = b"\x1b[1mB\x1b[m\x1b[4mU\x1b[m\x1b[7mR\x1b[m\x1b[3mI\x1b[m\
                      \x1b[31mC\x1b[m\x1b[38;5;208mP\x1b[m\x1b[38;2;10;20;30mT\x1b[m";
        let c = roundtrip(24, 80, bytes);
        let s = c.screen();
        assert!(s.cell(0, 0).unwrap().bold(), "bold");
        assert!(s.cell(0, 1).unwrap().underline(), "underline");
        assert!(s.cell(0, 2).unwrap().inverse(), "inverse");
        assert!(s.cell(0, 3).unwrap().italic(), "italic");
        assert_eq!(
            s.cell(0, 4).unwrap().fgcolor(),
            vt100::Color::Idx(1),
            "16-color red"
        );
        assert_eq!(
            s.cell(0, 5).unwrap().fgcolor(),
            vt100::Color::Idx(208),
            "256-color"
        );
        assert_eq!(
            s.cell(0, 6).unwrap().fgcolor(),
            vt100::Color::Rgb(10, 20, 30),
            "truecolor"
        );
    }

    #[test]
    fn cursor_motion_roundtrip() {
        // mosh emulation-cursor-motion: absolute positioning (CSI row;colH) places glyphs, which
        // must reconstruct on the client.
        let bytes = b"\x1b[H\x1b[J\x1b[1;1HA\x1b[1;10HB\x1b[4;1HC\x1b[24;1Hdone";
        let c = roundtrip(24, 80, bytes);
        let s = c.screen();
        assert_eq!(s.cell(0, 0).unwrap().contents(), "A");
        assert_eq!(s.cell(0, 9).unwrap().contents(), "B");
        assert_eq!(s.cell(3, 0).unwrap().contents(), "C");
        assert_eq!(row_text(s, 23), "done");
    }

    #[test]
    fn scroll_up_down_roundtrip() {
        // mosh emulation-scroll: SU (CSI N S) then SD (CSI N T) shift the screen; the result
        // must survive the round-trip. 24 numbered rows, scroll up 4, then down 2.
        let mut bytes = Vec::from(&b"\x1b[H\x1b[J"[..]);
        for i in 1..=24 {
            bytes.extend_from_slice(format!("\x1b[{i};1Hline{i}").as_bytes());
        }
        bytes.extend_from_slice(b"\x1b[4S\x1b[2T");
        let c = roundtrip(24, 80, &bytes);
        let s = c.screen();
        assert_eq!(
            row_text(s, 0),
            "",
            "two blank rows pushed in at the top after SD 2"
        );
        assert_eq!(
            row_text(s, 2),
            "line5",
            "line5 reached the top after SU 4, then down 2"
        );
        assert_eq!(row_text(s, 21), "line24", "last line still present");
    }

    #[test]
    fn insert_delete_lines_roundtrip_no_panic() {
        // mosh emulation-multiline-scroll: IL (CSI N L) / DL (CSI N M) with in- and out-of-range
        // counts must not panic and must round-trip exactly.
        let mut bytes = Vec::from(&b"\x1b[H\x1b[J"[..]);
        for i in 1..=24 {
            bytes.extend_from_slice(format!("\x1b[{i};1Hrow{i}").as_bytes());
        }
        for n in [0u32, 1, 2, 22, 26] {
            bytes.extend_from_slice(format!("\x1b[3;1H\x1b[{n}L").as_bytes());
            bytes.extend_from_slice(format!("\x1b[3;1H\x1b[{n}M").as_bytes());
        }
        let _ = roundtrip(24, 80, &bytes); // assertion: no panic + exact reconstruction
    }

    #[test]
    fn back_and_forward_tab_unsupported_but_roundtrip_clean() {
        // mosh emulation-back-tab: in mosh's hand-written emulator, CBT (CSI Z) / CHT (CSI I)
        // move between tab stops. The `vt100` crate moshers2 delegates to does NOT implement
        // them, so they are no-ops (a known, minor divergence from mosh). What we DO guarantee is
        // that the unhandled sequences round-trip identically server↔client and corrupt nothing.
        // If vt100 ever gains CBT/CHT, this test flips and should become the real mosh assertion
        // ("hello, world" / a forward-tabbed "ab      tab").
        let c = roundtrip(24, 80, b"hello, wurld\x1b[Zo");
        assert_eq!(
            row_text(c.screen(), 0),
            "hello, wurldo",
            "CBT currently a no-op in vt100"
        );
        let c2 = roundtrip(24, 80, b"ab\x1b[Itab");
        assert_eq!(
            row_text(c2.screen(), 0),
            "abtab",
            "CHT currently a no-op in vt100"
        );
    }

    #[test]
    fn column_80_no_premature_wrap_roundtrip() {
        // mosh emulation-80th-column: filling exactly to the last column leaves the cursor in the
        // deferred-wrap state; a following CRLF must not spill an extra blank wrapped line.
        let mut bytes = Vec::from(&b"\x1b[H\x1b[J"[..]);
        bytes.resize(bytes.len() + 80, b'E'); // 80 'E's, filling the row exactly
        bytes.extend_from_slice(b"\r\nM");
        let c = roundtrip(24, 80, &bytes);
        let s = c.screen();
        assert_eq!(row_text(s, 0), "E".repeat(80), "80 chars fill row 0");
        assert_eq!(
            s.cell(1, 0).unwrap().contents(),
            "M",
            "M lands on row 1, no spurious wrap row"
        );
    }

    #[test]
    fn wrap_across_incremental_frames() {
        // mosh emulation-wrap-across-frames: text filled to column 80 on frame N, then wrapped on
        // frame N+1, broke mosh's round-trip verification (the wrap flag lived on the Cell). It
        // must reconstruct across an INCREMENTAL diff (the persistent-parser path), not a repaint.
        let mut emu = ServerTerminal::new(24, 80, 0);
        emu.process(b"\x1b[H\x1b[J");
        emu.process(&[b'a'; 80]); // frame N: fill to col 80 -> deferred-wrap state
        let frame_n = emu.snapshot();
        let mut client = TerminalScreen::default();
        client.apply(&frame_n.diff_from(&TerminalScreen::default()));
        assert_eq!(client, frame_n);

        emu.process(b"b"); // frame N+1: one more char forces the wrap to row 1
        let frame_n1 = emu.snapshot();
        let diff = frame_n1.diff_from(&frame_n);
        assert!(
            diff.resize.is_none(),
            "incremental path, not a full repaint"
        );
        client.apply(&diff);
        assert_eq!(
            client, frame_n1,
            "wrap across frames must reconstruct incrementally"
        );
        assert_eq!(
            client.screen().cell(1, 0).unwrap().contents(),
            "b",
            "wrapped char on row 1"
        );
    }

    #[test]
    fn combining_mark_after_erase_does_not_panic() {
        // mosh unicode-combine-fallback-assert: a combining mark applied right after erasing the
        // cell it would attach to must not panic (mosh hit an internal assertion here).
        let _ = roundtrip(24, 80, b"0\x1b[1J\xcc\xb4");
    }

    #[test]
    fn combining_mark_on_blank_line_roundtrip() {
        // mosh unicode-later-combining: a combining mark printed on an otherwise-empty line gets
        // a base glyph and round-trips without dropping surrounding text.
        let c = roundtrip(24, 80, b"abc\n\xcc\x82\ndef\n");
        let contents = c.screen().contents();
        assert!(contents.contains("abc") && contents.contains("def"));
    }

    #[test]
    fn latin1_supplement_roundtrip() {
        // mosh emulation-ascii-iso-8859: ISO-8859-1 supplement characters render and round-trip.
        let c = roundtrip(24, 80, "àáâãäåæçèéêëìíîïñòóôõöøùúûüýþÿ".as_bytes());
        assert!(c.screen().contents().contains("àáâãä"));
    }
}
