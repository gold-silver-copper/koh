//! The server's live emulator: a `fux_vt::Parser` fed by the PTY, the title, icon, bell and
//! clipboard it reports, and the replies to the program's queries.

use crate::terminal::grid::RowCache;
use crate::terminal::{
    clamp_dims, Grid, Size, TerminalScreen, MAXIMUM_CLIPBOARD_SIZE, MAX_TITLE_LEN,
};
use fux_vt::{Event, Options, Parser, Sink};

/// Decode an OSC title/icon payload (lossy UTF-8) and clamp it to [`MAX_TITLE_LEN`] characters.
fn title_from(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .take(MAX_TITLE_LEN)
        .collect()
}

/// What the emulator reports beside the grid: fux-vt's [`Event`]s and the replies to queries.
#[derive(Default)]
struct Observed {
    title: String,
    icon: String,
    /// The remote-set clipboard payload (OSC 52, base64), capped at [`MAXIMUM_CLIPBOARD_SIZE`].
    clipboard: String,
    bell_count: u64,
    /// Query answers for the program's input, never part of the screen.
    host_replies: Vec<u8>,
}

impl Sink for Observed {
    fn reply(&mut self, bytes: &[u8]) {
        self.host_replies.extend_from_slice(bytes);
    }
    fn event(&mut self, event: Event<'_>) {
        match event {
            Event::Title(t) => self.title = title_from(t),
            Event::IconName(n) => self.icon = title_from(n),
            Event::Bell => self.bell_count = self.bell_count.saturating_add(1),
            // `data` is base64 already.
            Event::Clipboard { data, .. } if data.len() <= MAXIMUM_CLIPBOARD_SIZE => {
                self.clipboard = String::from_utf8_lossy(data).into_owned();
            }
            // An oversized clipboard is dropped; `_` is for events a later fux-vt adds.
            Event::Clipboard { .. } | _ => {}
        }
    }
}

/// The server's terminal: the live parser, and the [`TerminalScreen`] snapshots it sends.
///
/// fux-vt is panic-free and bounded: it keeps no control-string payload beyond the OSC
/// strings it reports, which it caps.
pub struct ServerTerminal {
    parser: Parser,
    observed: Observed,
    /// The program's exit code once it exited.
    exit_code: Option<u32>,
    /// The last snapshot's rows, which the next one shares where they are unchanged.
    rows: RowCache,
}

impl ServerTerminal {
    /// An emulator of this (clamped) size keeping `scrollback` lines. Fails only if fux-vt refuses
    /// the allocation (see [`MAX_SCROLLBACK`](crate::server::cli::MAX_SCROLLBACK)).
    pub fn new(rows: u16, cols: u16, scrollback: usize) -> Result<Self, fux_vt::Error> {
        let Size { rows, cols } = clamp_dims(Size { rows, cols });
        let options = Options {
            events: true,
            extended_replies: true,
        };
        Ok(Self {
            parser: Parser::with_options(rows, cols, scrollback, options)?,
            observed: Observed::default(),
            exit_code: None,
            rows: RowCache::default(),
        })
    }

    /// Record the shell's exit code; the next snapshot carries it to the client.
    pub fn set_exit_code(&mut self, code: u32) {
        self.exit_code = Some(code);
    }

    /// Feed the program's output. A failure (allocation or identity exhaustion) keeps what was
    /// applied and is logged.
    pub fn process(&mut self, bytes: &[u8]) {
        if let Err(e) = self.parser.process_with(bytes, &mut self.observed) {
            tracing::warn!(error = %e, "terminal emulator refused shell output");
        }
    }

    /// Take the replies to the program's queries, which the caller must write to its input.
    pub fn take_host_replies(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.observed.host_replies)
    }

    /// Resize to `size`, clamped: it comes from the peer. A refused resize keeps the size and is
    /// logged.
    pub fn resize(&mut self, size: Size) {
        let Size { rows, cols } = clamp_dims(size);
        if let Err(e) = self.parser.resize(rows, cols) {
            tracing::warn!(error = %e, rows, cols, "terminal emulator refused a resize");
        }
    }

    /// The size. Test-only.
    #[cfg(test)]
    pub fn size(&self) -> Size {
        let (rows, cols) = self.parser.screen().size();
        Size { rows, cols }
    }

    /// The window title. Test-only.
    #[cfg(test)]
    pub fn title(&self) -> &str {
        &self.observed.title
    }

    /// How many bells rang. Test-only.
    #[cfg(test)]
    pub fn bell_count(&self) -> u64 {
        self.observed.bell_count
    }

    /// Whether the program has application cursor keys (DECCKM) on.
    pub fn application_cursor(&self) -> bool {
        self.parser.screen().application_cursor()
    }

    /// A snapshot of the current screen. Rows unchanged since the last snapshot share its cells.
    pub fn snapshot(&mut self) -> TerminalScreen {
        TerminalScreen {
            grid: Grid::of(self.parser.screen(), &mut self.rows),
            title: self.observed.title.clone(),
            icon: self.observed.icon.clone(),
            clipboard: self.observed.clipboard.clone(),
            bell_count: self.observed.bell_count,
            exit_code: self.exit_code,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_cursor_position_report() {
        let mut t = ServerTerminal::new(24, 80, 0).expect("emulator");
        t.process(b"\x1b[5;3H"); // move cursor to row 5, col 3 (1-indexed input)
        t.process(b"\x1b[6n"); // DSR: report cursor position
        assert_eq!(t.take_host_replies(), b"\x1b[5;3R"); // 1-indexed report
                                                         // Drained: a second take is empty.
        assert_eq!(t.take_host_replies(), b"");
    }

    #[test]
    fn answers_device_attributes() {
        let mut t = ServerTerminal::new(24, 80, 0).expect("emulator");
        t.process(b"\x1b[c"); // primary DA: fux-vt answers as a VT100 with advanced video
        assert_eq!(t.take_host_replies(), b"\x1b[?1;2c");
        t.process(b"\x1b[>c"); // secondary DA
        assert_eq!(t.take_host_replies(), b"\x1b[>1;10;0c");
    }

    #[test]
    fn answers_decxcpr_and_decrqm() {
        let mut t = ServerTerminal::new(24, 80, 0).expect("emulator");
        t.process(b"\x1b[5;3H\x1b[?6n");
        assert_eq!(t.take_host_replies(), b"\x1b[?5;3R");
        t.process(b"\x1b[?2004$p\x1b[?2004h\x1b[?2004$p\x1b[?4242$p");
        assert_eq!(
            t.take_host_replies(),
            b"\x1b[?2004;2$y\x1b[?2004;1$y\x1b[?4242;0$y"
        );
    }

    #[test]
    fn title_icon_bell_clipboard_captured() {
        let mut t = ServerTerminal::new(24, 80, 0).expect("emulator");
        t.process(b"\x1b]2;my-title\x07\x07\x1b]1;my-icon\x07\x1b]52;c;aGVsbG8=\x07");
        assert_eq!(t.title(), "my-title");
        assert_eq!(t.bell_count(), 1);
        let snap = t.snapshot();
        assert_eq!(snap.title(), "my-title");
        assert_eq!(snap.icon(), "my-icon", "snapshot carries the icon name");
        assert_eq!(
            snap.clipboard(),
            "aGVsbG8=",
            "snapshot carries the OSC-52 clipboard"
        );
        assert_eq!(snap.bell_count(), 1, "snapshot carries the bell count");
    }

    #[test]
    fn server_resize_clamps_oom_and_zero() {
        use crate::terminal::{MAX_DIM, MIN_DIM};
        // The server emulator must clamp a peer-controlled resize before the grid is allocated:
        // a giant resize would OOM-abort the (cross-tenant) server.
        let mut t = ServerTerminal::new(24, 80, 0).expect("emulator");
        t.resize(Size::new(65000, 65000)); // must not OOM
        assert_eq!(
            t.size(),
            Size::new(MAX_DIM, MAX_DIM),
            "giant resize clamped to MAX_DIM"
        );
        t.resize(Size::new(0, 0)); // must not panic
        assert_eq!(
            t.size(),
            Size::new(MIN_DIM, MIN_DIM),
            "zero resize clamped to MIN_DIM"
        );
        // Wrappy/wide shell output into the smallest clamped grid is fine.
        t.process("AAAA日本🦀\r\nBBBB\r\n".repeat(8).as_bytes());
        let _ = t.snapshot();
        // A normal resize is untouched, and a snapshot after a clamped resize is still coherent.
        t.resize(Size::new(40, 120));
        assert_eq!(t.size(), Size::new(40, 120));
        let _ = t.snapshot();
    }

    #[test]
    fn max_scrollback_fits_the_largest_screen() {
        // `MAX_SCROLLBACK` must leave room for a MAX_DIM×MAX_DIM screen in fux-vt's per-buffer
        // cell limit, or `koh serve --scrollback <max>` would fail to start or refuse a resize.
        use crate::terminal::MAX_DIM;
        let history = usize::try_from(crate::server::cli::MAX_SCROLLBACK).expect("fits usize");
        let mut t = ServerTerminal::new(24, 80, history).expect("default size at max scrollback");
        t.resize(Size::new(MAX_DIM, MAX_DIM));
        assert_eq!(
            t.size(),
            Size::new(MAX_DIM, MAX_DIM),
            "largest resize accepted"
        );
        assert!(ServerTerminal::new(MAX_DIM, MAX_DIM, history).is_ok());
    }

    #[test]
    fn oversized_clipboard_is_dropped() {
        // A clipboard set above the cap must not be synced (anti-amplification).
        let mut t = ServerTerminal::new(24, 80, 0).expect("emulator");
        let big = "A".repeat(MAXIMUM_CLIPBOARD_SIZE + 1);
        t.process(format!("\x1b]52;c;{big}\x07").as_bytes());
        assert_eq!(t.snapshot().clipboard(), "", "oversized clipboard dropped");
    }

    #[test]
    fn oversized_title_is_clamped() {
        // A runaway/hostile OSC title is clamped to MAX_TITLE_LEN chars (mosh's parse-time cap),
        // not stored unbounded.
        let mut t = ServerTerminal::new(24, 80, 0).expect("emulator");
        let huge = "x".repeat(MAX_TITLE_LEN + 500);
        t.process(format!("\x1b]2;{huge}\x07").as_bytes());
        assert_eq!(
            t.title().chars().count(),
            MAX_TITLE_LEN,
            "title clamped to the cap"
        );
        // A title within the cap is untouched.
        t.process(b"\x1b]2;short\x07");
        assert_eq!(t.title(), "short");
    }

    #[test]
    fn unterminated_control_strings_are_bounded_and_recover() {
        // fux-vt retains no DCS/APC/PM/SOS payload and caps a pending OSC at its payload limit, so
        // a runaway string can't grow memory; terminating it resumes normal output.
        let mut terminal = ServerTerminal::new(24, 80, 0).expect("emulator");
        for introducer in [&b"\x1b]2;"[..], b"\x1bP", b"\x1bX", b"\x1b_", b"\x1b^"] {
            terminal.process(b"before");
            terminal.process(introducer);
            for _ in 0..32 {
                terminal.process(&[b'x'; 16 * 1024]);
            }
            terminal.process(b"\x1b\\after\r\n");
        }
        let contents = terminal.snapshot().screen().contents();
        assert_eq!(contents.matches("beforeafter").count(), 5, "{contents:?}");
        assert_eq!(
            terminal.title(),
            "",
            "an over-limit title is dropped, not truncated"
        );
    }

    #[test]
    fn split_osc_and_csi_keep_their_meaning() {
        let mut terminal = ServerTerminal::new(24, 80, 0).expect("emulator");
        for chunk in [
            &b"\x1b"[..],
            &b"]2;split"[..],
            &b" title\x1b"[..],
            &b"\\\x1b"[..],
            &b"[5;3Hok"[..],
        ] {
            terminal.process(chunk);
        }
        assert_eq!(terminal.title(), "split title");
        assert!(terminal.snapshot().screen().contents().contains("ok"));
    }
}
