//! The server's live emulator: a `fux_vt::Parser` fed by the PTY, the title, icon, bell and
//! clipboard it reports, and the replies to the program's queries.

use crate::terminal::grid::RowCache;
use crate::terminal::{
    clamp_dims, Grid, Size, TerminalScreen, MAXIMUM_CLIPBOARD_SIZE, MAX_TITLE_LEN,
};
use std::time::{Duration, Instant};

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
            // `data` is base64 already. A query (`?`) asks for the clipboard, which koh never
            // reads, so it is not one to set.
            Event::Clipboard { data, .. }
                if data.len() <= MAXIMUM_CLIPBOARD_SIZE && data != b"?" =>
            {
                self.clipboard = String::from_utf8_lossy(data).into_owned();
            }
            // An oversized clipboard is dropped; `_` is for events a later fux-vt adds.
            Event::Clipboard { .. } | _ => {}
        }
    }
}

/// Who the server's terminal says it is: koh, at this version.
///
/// It answers device attributes (`CSI c`, `CSI > c`) and XTVERSION (`CSI > q`) with it. A name no
/// program knows makes no program assume a feature of a terminal it does know.
pub const IDENTITY: fux_vt::Identity = fux_vt::Identity {
    name: "koh",
    version: env!("CARGO_PKG_VERSION"),
};

/// What the server's terminal does beyond fux-vt's defaults, each because koh carries it to the
/// user:
///
/// - events: the title, icon, bell and clipboard, which the client mirrors;
/// - extended replies: DECRQM, DECXCPR and secondary DA, as a terminal answers them;
/// - in-band resize (mode 2048) and the size query (`CSI 18 t`): koh knows the size, and tells a
///   program that asks, after a resize too;
/// - the palette: a program's colours (OSC 4, 10, 11 and the rest) are kept and answered, and
///   snapshots draw them as RGB, so the user's own palette never changes and nothing is left
///   changed when they detach;
/// - reflow: a resize re-wraps the primary screen and its history, as the user's terminal would;
/// - koh's [`IDENTITY`].
///
/// Left off: the kitty keyboard protocol (koh forwards the keys the user's terminal sends, so a
/// program told it may use the protocol would get keys it did not ask for); prompt marks (koh does
/// not carry scrollback, where they are used); rectangle checksums (a program reading back its
/// screen, which xterm refuses by default).
pub const OPTIONS: Options = Options::new()
    .with_events(true)
    .with_extended_replies(true)
    .with_in_band_resize(true)
    .with_size_reports(true)
    .with_palette(true)
    .with_reflow(true)
    .with_identity(Some(IDENTITY));

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
    /// The screen as it was when the program last began a frame (synchronized output), a whole
    /// one, until taken.
    frame_start: Option<TerminalScreen>,
    /// Where the program's output ends a frame.
    frame_ends: FrameEnds,
}

impl ServerTerminal {
    /// An emulator of this (clamped) size keeping `scrollback` lines. Fails only if fux-vt refuses
    /// the allocation (see [`MAX_SCROLLBACK`](crate::server::cli::MAX_SCROLLBACK)).
    pub fn new(rows: u16, cols: u16, scrollback: usize) -> Result<Self, fux_vt::Error> {
        let Size { rows, cols } = clamp_dims(Size { rows, cols });
        Ok(Self {
            parser: Parser::with_options(rows, cols, scrollback, OPTIONS)?,
            observed: Observed::default(),
            exit_code: None,
            rows: RowCache::default(),
            frame_start: None,
            frame_ends: FrameEnds::default(),
        })
    }

    /// Record the shell's exit code; the next snapshot carries it to the client.
    pub fn set_exit_code(&mut self, code: u32) {
        self.exit_code = Some(code);
    }

    /// Feed the program's output. A failure (allocation or identity exhaustion) keeps what was
    /// applied and is logged.
    ///
    /// Where the program begins a frame (synchronized output, `CSI ? 2026 h`), the screen as it was
    /// is kept, for [`FrameHold`] to send while the frame is drawn.
    pub fn process(&mut self, bytes: &[u8]) {
        // Fed in pieces that each end at an ESU, so that whether a frame was being drawn just
        // before a BSU is known: at the start of its piece, or after a BSU earlier in it.
        let mut start = 0;
        let ends = self.frame_ends.after_each(bytes);
        for end in ends.into_iter().chain(std::iter::once(bytes.len())) {
            let mut rest = bytes.get(start..end).unwrap_or_default();
            start = end;
            loop {
                let drawing = self.synchronized();
                match self.parser.process_until_frame(rest, &mut self.observed) {
                    Ok(Some(taken)) if taken > 0 => {
                        if !drawing {
                            self.frame_start = Some(self.snapshot());
                        }
                        rest = rest.get(taken..).unwrap_or_default();
                    }
                    Ok(Some(_) | None) => break,
                    Err(e) => {
                        tracing::warn!(error = %e, "terminal emulator refused shell output");
                        break;
                    }
                }
            }
        }
    }

    /// Whether the program is drawing a frame it wants shown whole (synchronized output).
    pub fn synchronized(&self) -> bool {
        self.parser.screen().synchronized_output()
    }

    /// The screen as it was when the program last began a frame, if not taken since.
    pub fn take_frame_start(&mut self) -> Option<TerminalScreen> {
        self.frame_start.take()
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

    /// The report a program that set in-band resize (mode 2048) is sent after a resize, for its
    /// input; `None` if it did not set it.
    pub fn resize_report(&self) -> Option<Vec<u8>> {
        self.parser.resize_report()
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

/// Finds where a program ends synchronized output (ESU, `CSI ? … 2026 … l`) in its output, its state
/// carried from one read to the next so that a sequence split between them is found too.
#[derive(Debug, Default)]
struct FrameEnds {
    state: Scan,
    /// The parameters of the private CSI being read, up to [`FrameEnds::PARAMS`] bytes.
    params: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Scan {
    #[default]
    Ground,
    Escape,
    /// After `ESC [`.
    Csi,
    /// In a CSI that starts with `?`, whose parameters may name 2026.
    Private,
    /// In a CSI that cannot be an ESU, to its final byte.
    Other,
}

impl FrameEnds {
    /// The longest parameter list read; a longer one is not an ESU koh looks for.
    const PARAMS: usize = 64;

    /// The offsets in `bytes` just past each ESU.
    fn after_each(&mut self, bytes: &[u8]) -> Vec<usize> {
        let mut ends = Vec::new();
        for (at, &byte) in bytes.iter().enumerate() {
            self.state = match (self.state, byte) {
                (_, 0x1b) => Scan::Escape,
                (Scan::Escape, b'[') => Scan::Csi,
                (Scan::Csi, b'?') => {
                    self.params.clear();
                    Scan::Private
                }
                (Scan::Private, b'0'..=b'9' | b';') if self.params.len() < Self::PARAMS => {
                    self.params.push(byte);
                    Scan::Private
                }
                (Scan::Private, b'l')
                    if self.params.split(|&b| b == b';').any(|p| p == b"2026") =>
                {
                    ends.push(at.saturating_add(1));
                    Scan::Ground
                }
                (Scan::Csi | Scan::Private | Scan::Other, 0x40..=0x7e) | (Scan::Escape, _) => {
                    Scan::Ground
                }
                (Scan::Csi | Scan::Private | Scan::Other, _) => Scan::Other,
                (Scan::Ground, _) => Scan::Ground,
            };
        }
        ends
    }
}

/// The longest a program's frame is held before its screen is sent anyway, so that a program that
/// stopped mid-frame cannot freeze the screen. Terminals bound it between 100 and 200 ms.
pub const FRAME_HOLD: Duration = Duration::from_millis(150);

/// Which screen a session sends while a program draws a frame it wants shown whole: not the
/// half-drawn one.
///
/// A program asks for it with synchronized output (DEC 2026). While the frame is drawn, the screen as it was when
/// the frame began goes out, once; at its end (ESU, a resize or a reset), the screen. A frame held
/// longer than [`FRAME_HOLD`] is let go, and the screen goes out as if the program had ended it.
/// Without I/O: the session gives it the time.
#[derive(Debug, Default)]
pub struct FrameHold {
    /// When the frame held was first seen.
    since: Option<Instant>,
    /// Whether the frame held was let go after [`FRAME_HOLD`].
    released: bool,
}

impl FrameHold {
    /// After the program's output was fed to `emu`, at `now`: the screen to send, if any.
    pub fn after_output(
        &mut self,
        emu: &mut ServerTerminal,
        now: Instant,
    ) -> Option<TerminalScreen> {
        let started = emu.take_frame_start();
        if !emu.synchronized() {
            self.since = None;
            self.released = false;
            return Some(emu.snapshot());
        }
        if started.is_some() {
            // A frame began in this output, so any before it ended: hold this one from now, even
            // if the one before was let go and ended within the same output.
            self.since = Some(now);
            self.released = false;
            return started;
        }
        let since = *self.since.get_or_insert(now);
        if self.released || now.saturating_duration_since(since) >= FRAME_HOLD {
            self.released = true;
            return Some(emu.snapshot());
        }
        started
    }

    /// When the frame held is let go, if one is held.
    pub fn deadline(&self) -> Option<Instant> {
        if self.released {
            return None;
        }
        self.since.and_then(|since| since.checked_add(FRAME_HOLD))
    }

    /// At `now`, past [`FrameHold::deadline`]: the screen to send, if a frame is still held.
    pub fn expire(&mut self, emu: &mut ServerTerminal, now: Instant) -> Option<TerminalScreen> {
        if !emu.synchronized() {
            self.since = None;
            self.released = false;
            return None;
        }
        if self.deadline().is_some_and(|deadline| now >= deadline) {
            self.released = true;
            return Some(emu.snapshot());
        }
        None
    }

    /// Whether a frame is held: the screen sent is the one from before it began.
    pub fn holding(&self) -> bool {
        self.since.is_some() && !self.released
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::terminal::Grid;
    use std::time::{Duration, Instant};

    /// Output that changes rows in every way: text, rewriting a row the same, erasing, scrolling,
    /// inserted and deleted lines, the alternate screen, a reset.
    const PIECES: [&str; 12] = [
        "text",
        "\r\n",
        "\x1b[H",
        "\x1b[Htext",
        "\x1b[2J",
        "\x1b[K",
        "\x1b[2;4r\x1b[4;1H\n\x1b[r",
        "\x1b[2L",
        "\x1b[M",
        "\x1b[?1049h",
        "\x1b[?1049l",
        "\x1bc",
    ];

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

        /// A snapshot that reuses the last one's rows (by fux-vt row id and version) shows exactly
        /// what one built from nothing does.
        #[test]
        fn a_snapshot_reusing_rows_shows_the_emulator_exactly(
            steps in proptest::collection::vec(
                (
                    proptest::collection::vec(0..PIECES.len(), 0..4),
                    proptest::option::of((2u16..8, 2u16..12)),
                ),
                1..16,
            ),
        ) {
            let mut t = ServerTerminal::new(5, 10, 3).expect("emulator");
            for (pieces, resize) in steps {
                for piece in pieces {
                    t.process(PIECES[piece].as_bytes());
                }
                if let Some((rows, cols)) = resize {
                    t.resize(Size::new(rows, cols));
                }
                let reused = t.snapshot();
                let fresh = Grid::of(t.parser.screen(), &mut RowCache::default());
                proptest::prop_assert_eq!(reused.screen(), &fresh);
            }
        }
    }

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
    fn answers_device_attributes_and_xtversion_as_koh() {
        let mut t = ServerTerminal::new(24, 80, 0).expect("emulator");
        t.process(b"\x1b[c"); // primary DA: a VT220-class terminal with ANSI colour
        assert_eq!(t.take_host_replies(), b"\x1b[?62;22c");
        // Secondary DA: koh's version as major * 10000 + minor * 100 + patch.
        let mut parts = env!("CARGO_PKG_VERSION")
            .split('.')
            .map(|p| p.parse::<u32>().expect("a number"));
        let (major, minor, patch) = (
            parts.next().unwrap(),
            parts.next().unwrap(),
            parts.next().unwrap(),
        );
        t.process(b"\x1b[>c");
        assert_eq!(
            t.take_host_replies(),
            format!("\x1b[>1;{};0c", major * 10000 + minor * 100 + patch).as_bytes()
        );
        t.process(b"\x1b[>q"); // XTVERSION
        assert_eq!(
            t.take_host_replies(),
            format!("\x1bP>|koh {}\x1b\\", env!("CARGO_PKG_VERSION")).as_bytes()
        );
    }

    #[test]
    fn answers_the_size_query_and_reports_a_resize_to_a_program_that_asked() {
        let mut t = ServerTerminal::new(24, 80, 0).expect("emulator");
        t.process(b"\x1b[18t");
        assert_eq!(t.take_host_replies(), b"\x1b[8;24;80t");
        // No report before a program sets mode 2048.
        t.resize(Size::new(30, 90));
        assert_eq!(t.resize_report(), None);
        t.process(b"\x1b[?2048h");
        // Setting it reports the size at once.
        assert_eq!(t.take_host_replies(), b"\x1b[48;30;90;0;0t");
        t.resize(Size::new(20, 60));
        assert_eq!(
            t.resize_report().as_deref(),
            Some(&b"\x1b[48;20;60;0;0t"[..])
        );
    }

    #[test]
    fn a_programs_colours_are_drawn_as_rgb_until_it_resets_them() {
        use fux_vt::Color;
        let mut t = ServerTerminal::new(4, 20, 0).expect("emulator");
        t.process(b"\x1b[31mR\x1b[39mD");
        let colours = |t: &mut ServerTerminal, col: u16| {
            let snapshot = t.snapshot();
            let cell = snapshot.screen().cell(0, col).expect("a cell");
            (cell.fgcolor(), cell.bgcolor())
        };
        assert_eq!(colours(&mut t, 0), (Color::Idx(1), Color::Default));
        // The row's cells do not change, only how they are drawn: the snapshot draws them anew.
        t.process(b"\x1b]4;1;#ff0000\x1b\\\x1b]10;rgb:11/22/33\x07\x1b]11;#000080\x07");
        let navy = Color::Rgb(0, 0, 0x80);
        assert_eq!(colours(&mut t, 0), (Color::Rgb(0xff, 0, 0), navy));
        assert_eq!(colours(&mut t, 1), (Color::Rgb(0x11, 0x22, 0x33), navy));
        assert_eq!(
            colours(&mut t, 7).1,
            navy,
            "a blank cell is in the background set"
        );
        // Reset, each colour is the user's terminal's again.
        t.process(b"\x1b]104;1\x07\x1b]110\x07\x1b]111\x07");
        assert_eq!(colours(&mut t, 0), (Color::Idx(1), Color::Default));
        assert_eq!(colours(&mut t, 1), (Color::Default, Color::Default));
        // The program is answered with the colours it set.
        t.process(b"\x1b]4;1;#00ff00\x07\x1b]4;1;?\x07");
        assert_eq!(t.take_host_replies(), b"\x1b]4;1;rgb:0000/ffff/0000\x07");
    }

    /// The text of row 0 of `screen`.
    fn top(screen: &TerminalScreen) -> String {
        screen
            .screen()
            .contents()
            .lines()
            .next()
            .unwrap_or_default()
            .trim_end()
            .to_owned()
    }

    #[test]
    fn a_frame_being_drawn_is_not_sent_half_drawn() {
        let mut t = ServerTerminal::new(4, 20, 0).expect("emulator");
        let mut hold = FrameHold::default();
        let start = Instant::now();
        let at = |ms: u64| start + Duration::from_millis(ms);
        t.process(b"old frame");
        assert_eq!(top(&hold.after_output(&mut t, at(0)).unwrap()), "old frame");
        // The program begins a frame and draws half of it: the screen from before goes out, once.
        t.process(b"\x1b[?2026h\x1b[H\x1b[2Knew");
        assert_eq!(
            top(&hold.after_output(&mut t, at(10)).unwrap()),
            "old frame"
        );
        assert!(hold.holding());
        t.process(b" fra");
        assert!(
            hold.after_output(&mut t, at(20)).is_none(),
            "nothing while it draws"
        );
        // It ends the frame: the whole of it goes out.
        t.process(b"me\x1b[?2026l");
        assert_eq!(
            top(&hold.after_output(&mut t, at(30)).unwrap()),
            "new frame"
        );
        assert!(!hold.holding() && hold.deadline().is_none());
        // A whole frame in one read is sent as it is.
        t.process(b"\x1b[?2026h\x1b[H\x1b[2Kthird\x1b[?2026l");
        assert_eq!(top(&hold.after_output(&mut t, at(40)).unwrap()), "third");
    }

    #[test]
    fn a_frame_never_ended_is_let_go_after_the_hold() {
        let mut t = ServerTerminal::new(4, 20, 0).expect("emulator");
        let mut hold = FrameHold::default();
        let start = Instant::now();
        let at = |ms: u64| start + Duration::from_millis(ms);
        t.process(b"before\x1b[?2026h\x1b[H\x1b[2Kstuck");
        assert_eq!(top(&hold.after_output(&mut t, at(0)).unwrap()), "before");
        assert_eq!(hold.deadline(), Some(at(0) + FRAME_HOLD));
        assert!(
            hold.expire(&mut t, at(100)).is_none(),
            "not before the deadline"
        );
        assert_eq!(top(&hold.expire(&mut t, at(150)).unwrap()), "stuck");
        assert!(hold.deadline().is_none() && !hold.holding());
        // Let go, later output goes out as it comes, until the frame ends.
        t.process(b"!");
        assert_eq!(top(&hold.after_output(&mut t, at(160)).unwrap()), "stuck!");
        t.process(b"\x1b[?2026l\x1b[?2026h");
        assert!(hold.after_output(&mut t, at(170)).is_some());
        assert!(hold.holding(), "a new frame is held again");
    }

    #[test]
    fn a_frame_end_split_between_reads_is_found() {
        let mut t = ServerTerminal::new(4, 20, 0).expect("emulator");
        t.process(b"\x1b[?2026h\x1b[2Kone");
        drop(t.take_frame_start());
        // The ESU in two reads, then the next frame begins: it starts from the frame ended.
        t.process(b"\x1b[?20");
        t.process(b"26l\x1b[?2026h\x1b[H\x1b[2Ktw");
        assert_eq!(top(&t.take_frame_start().expect("a frame began")), "one");
        // A BSU again while the frame is drawn begins none.
        t.process(b"o\x1b[?2026h");
        assert!(t.take_frame_start().is_none());
    }

    #[test]
    fn a_resize_ends_the_frame_held() {
        let mut t = ServerTerminal::new(4, 20, 0).expect("emulator");
        let mut hold = FrameHold::default();
        let now = Instant::now();
        t.process(b"a\x1b[?2026hb");
        assert!(hold.after_output(&mut t, now).is_some());
        t.resize(Size::new(5, 20));
        assert!(!t.synchronized());
        assert!(hold.expire(&mut t, now + FRAME_HOLD).is_none());
        assert!(!hold.holding());
    }

    #[test]
    fn a_clipboard_query_sets_nothing() {
        let mut t = ServerTerminal::new(4, 20, 0).expect("emulator");
        t.process(b"\x1b]52;c;aGVsbG8=\x07\x1b]52;c;?\x07");
        assert_eq!(t.snapshot().clipboard(), "aGVsbG8=");
        assert_eq!(t.take_host_replies(), b"", "nor is it answered");
    }

    #[test]
    fn a_resize_rewraps_the_primary_screen() {
        let mut t = ServerTerminal::new(4, 20, 100).expect("emulator");
        t.process(b"0123456789abcdefghijKLMNO");
        t.resize(Size::new(4, 30));
        let snapshot = t.snapshot();
        let first = (0..30)
            .filter_map(|col| snapshot.screen().cell(0, col))
            .map(|c| c.contents().to_owned())
            .collect::<String>();
        assert_eq!(
            first, "0123456789abcdefghijKLMNO",
            "the wrapped line is one row again"
        );
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
