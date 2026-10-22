//! The server's live emulator: a `fux_vt::Parser` fed by the PTY, which answers the program's
//! questions, encodes the client's input as the program asked, and keeps the screen a client is
//! redrawn from, the shell's commands and the window title.

use crate::request::MAX_TITLE;
use crate::terminal::Size;

use crate::events::{InputEvent, WireColours};
use fux_vt::keys::colour::Colours;
use fux_vt::keys::encode::{key_bytes, paste};
use fux_vt::{Event, Options, Parser, Sink, Unhandled};

/// Decode an OSC title payload (lossy UTF-8) and clamp it to [`MAX_TITLE`] characters.
fn title_from(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .take(MAX_TITLE)
        .collect()
}

/// What the emulator reports beside the screen: fux-vt's [`Event`]s and the replies to queries.
#[derive(Default)]
struct Observed {
    title: String,
    bell_count: u64,
    /// Query answers for the program's input, never part of the screen.
    host_replies: Vec<u8>,
    /// What the user's terminal said of its colours, as the client last told: the program's
    /// queries of the foreground and background (OSC 10, 11) and of the scheme (`CSI ? 996 n`) are
    /// answered from it, unless the program set those colours itself (fux-vt answers those).
    colours: Colours,
}

impl Sink for Observed {
    fn reply(&mut self, bytes: &[u8]) {
        self.host_replies.extend_from_slice(bytes);
    }
    fn event(&mut self, event: Event<'_>) {
        match event {
            Event::Title(t) => self.title = title_from(t),
            Event::Bell => self.bell_count = self.bell_count.saturating_add(1),
            // A colour no program set: the user's terminal's, if the client said it; else
            // unanswered, as a terminal that does not know it would leave it.
            Event::ColorQuery { number, bel } => {
                if let Some(answer) = self.colours.answer(number, bel) {
                    self.host_replies.extend_from_slice(&answer);
                }
            }
            // The clipboard and notifications reach the user's terminal as the program wrote them.
            Event::IconName(_) | Event::Clipboard { .. } | Event::Notification(_) => {}
        }
    }
    fn unhandled(&mut self, sequence: Unhandled<'_>) {
        // The scheme query, `CSI ? 996 n`, which fux-vt leaves to its host.
        if let Unhandled::Csi {
            params,
            intermediates: b"?",
            action: b'n',
        } = sequence
        {
            let mut groups = params.groups();
            if groups.next() == Some(&[996][..]) && groups.next().is_none() {
                if let Some(scheme) = self.colours.scheme {
                    self.host_replies.extend_from_slice(scheme.report());
                }
            }
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

/// What the server's terminal does beyond fux-vt's defaults.
///
/// It answers every question a program asks (the user's terminal never sees one,
/// `crate::stream`), so it says what a terminal koh relays to can be asked:
///
/// - events: the title and the bell, for listings and the bell hook;
/// - extended replies: DECRQM, DECXCPR and secondary DA, as a terminal answers them;
/// - in-band resize (mode 2048) and the size query (`CSI 18 t`): koh knows the size, and tells a
///   program that asks, after a resize too;
/// - the palette: a program's colours (OSC 4, 10, 11 and the rest) are kept and answered;
/// - reflow: a resize re-wraps the primary screen and its history, as the user's terminal would;
/// - setting reports (DECRQSS) for the pen, the cursor shape and the margins;
/// - hyperlinks (OSC 8), which a redraw paints again;
/// - the kitty keyboard protocol: the client sends decoded keys and the server encodes each as
///   the program asked ([`ServerTerminal::encode_input`]), so a program that pushed flags gets
///   kitty's keys from any terminal;
/// - colour scheme updates (mode 2031): a program that subscribes hears when the user's terminal
///   reports a new scheme;
/// - the shell's marks (OSC 133), for `koh wait`, `koh output --last` and the state report;
/// - koh's [`IDENTITY`].
///
/// Left off: rectangle checksums (a program reading back its screen, which xterm refuses by
/// default).
pub const OPTIONS: Options = Options::new()
    .with(fux_vt::Feature::KittyKeyboard)
    .with(fux_vt::Feature::ColorSchemeUpdates)
    .with(fux_vt::Feature::Events)
    .with(fux_vt::Feature::ExtendedReplies)
    .with(fux_vt::Feature::InBandResize)
    .with(fux_vt::Feature::SizeReports)
    .with(fux_vt::Feature::Palette)
    .with(fux_vt::Feature::Reflow)
    .with(fux_vt::Feature::SettingReports)
    .with(fux_vt::Feature::Hyperlinks)
    .with(fux_vt::Feature::PromptMarks)
    .with_identity(Some(IDENTITY));

/// The server's terminal: the live parser and what it observed.
///
/// fux-vt is panic-free and bounded: it keeps no control-string payload beyond the OSC
/// strings it reports, which it caps.
pub struct ServerTerminal {
    parser: Parser,
    observed: Observed,
}

impl ServerTerminal {
    /// An emulator of this (clamped) size keeping `history_bytes` of history. Fails only if fux-vt
    /// refuses the allocation.
    pub fn new(rows: u16, cols: u16, history_bytes: usize) -> Result<Self, fux_vt::Error> {
        let size = super::host_size(Size { rows, cols });
        Ok(Self {
            parser: Parser::with_options(size, history_bytes, OPTIONS)?,
            observed: Observed::default(),
        })
    }

    /// Append the bytes the program gets for `events`, each encoded as it asked: keys in its
    /// keyboard mode (DECCKM, the kitty flags, modifyOtherKeys), mouse events in its tracking
    /// mode and encoding (none if it asked for none), focus changes if it set mode 1004, and
    /// pastes framed if it set bracketed paste, their end markers removed, so nothing in one can
    /// end its frame early.
    pub fn encode_input(&self, events: &[InputEvent], out: &mut Vec<u8>) {
        for event in events {
            let screen = self.parser.screen();
            match event {
                InputEvent::Key(key) => key_bytes(key.stroke(), screen.key_mode(), out),
                InputEvent::Mouse(mouse) => {
                    screen.encode_mouse(mouse.event(), out);
                }
                InputEvent::Focus(focused) => {
                    out.extend_from_slice(screen.focus_report(*focused).unwrap_or_default());
                }
                InputEvent::Paste(text) => {
                    paste(text, screen.mode(fux_vt::Mode::BracketedPaste), out);
                }
            }
        }
    }

    /// What the user's terminal said of its colours, replacing what an earlier client said; the
    /// report a program that subscribed to scheme changes (mode 2031) is owed, if the scheme
    /// changed from one known before.
    pub fn set_colours(&mut self, colours: &WireColours) -> Vec<u8> {
        let colours_now = colours.colours();
        let before = self.observed.colours.scheme;
        self.observed.colours = colours_now;
        // Each entry the client gave, and none it did not: a reattaching client's palette
        // replaces the last client's whole. fux-vt answers a program's query of an entry it has
        // not set (OSC 4) with it; one the program set wins.
        self.parser
            .set_host_palette(colours.palette.map(|entry| entry.map(Into::into)));
        match (before, colours_now.scheme) {
            (Some(before), Some(now))
                if before != now && self.parser.screen().mode(fux_vt::Mode::ColorSchemeUpdates) =>
            {
                now.report().to_vec()
            }
            _ => Vec::new(),
        }
    }

    /// The program's screen as it is now, its modes among it.
    pub fn live(&self) -> &fux_vt::Screen {
        self.parser.screen()
    }

    /// Count only the shell marks (OSC 133) that carry `nonce=NONCE`, the marks of a shell given
    /// it; `None`, every one.
    pub fn require_mark_nonce(&mut self, nonce: Option<&[u8]>) {
        self.parser.require_mark_nonce(nonce, None);
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

    /// The window title the program set last.
    pub fn title(&self) -> &str {
        &self.observed.title
    }

    /// How often the bell rang.
    pub const fn bell_count(&self) -> u64 {
        self.observed.bell_count
    }

    /// Resize to `size`, clamped: it comes from the peer. Whether that changed the size; a
    /// refused resize keeps the size and is logged.
    pub fn resize(&mut self, size: Size) -> bool {
        let size = super::host_size(size);
        if self.parser.screen().size() == size {
            return false;
        }
        if let Err(e) = self.parser.resize(size) {
            tracing::warn!(error = %e, rows = size.rows(), cols = size.cols(), "terminal emulator refused a resize");
            return false;
        }
        true
    }

    /// The report a program that set in-band resize (mode 2048) is sent after a resize, for its
    /// input; `None` if it did not set it.
    pub fn resize_report(&self) -> Option<Vec<u8>> {
        self.parser.resize_report()
    }

    /// The text the screen shows, soft-wrapped rows joined, at most `max` bytes: none of the
    /// blank rows below the last that shows anything (a glyph, or a colour).
    pub fn screen_text(&self, max: usize) -> String {
        let screen = self.parser.screen();
        let mut rows: Vec<fux_vt::Row<'_>> = screen.rows().skip(screen.history_len()).collect();
        let blank = |row: &fux_vt::Row<'_>| {
            row.cells()
                .all(|c| !c.has_contents() && c.attributes() == fux_vt::Attributes::default())
        };
        let shown = rows
            .iter()
            .rposition(|row| !blank(row))
            .map_or(0, |n| n.saturating_add(1));
        rows.truncate(shown);
        super::text_of(rows.into_iter(), 0, None, max)
    }

    /// The output of the last command the shell finished, as the primary screen and its history
    /// still hold it, at most `max` bytes (its end); `None` if no command finished, or its output
    /// scrolled out of the history.
    pub fn last_output(&self, max: usize) -> Option<String> {
        let screen = self.parser.screen();
        let (start, end) = screen.commands().last_output?;
        let rows: Vec<fux_vt::Row<'_>> = screen.main_rows().collect();
        let from = rows.iter().position(|row| row.id() == start.row)?;
        let to = rows.iter().position(|row| row.id() == end.row)?;
        let span = rows.get(from..=to)?;
        // The output ends where the end mark was: a mark at a row's first column ends it on the
        // row before.
        let (span, to_col) = match (span.split_last(), end.col) {
            (Some((_, before)), 0) if !before.is_empty() => {
                (before, before.last().map(fux_vt::Row::len))
            }
            _ => (span, Some(usize::from(end.col).saturating_sub(1))),
        };
        Some(super::text_of(
            span.iter().copied(),
            usize::from(start.col),
            to_col,
            max,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_last_commands_output_and_the_screens_text() {
        let mut t = ServerTerminal::new(4, 20, 1 << 20).expect("emulator");
        t.process(
            b"$ ls\r\n\x1b]133;C\x07one\r\n0123456789abcdefghijklmn\r\n\x1b]133;D;0\x07\
              \x1b]133;A\x07$ ",
        );
        assert_eq!(
            t.last_output(1 << 20).as_deref(),
            Some("one\n0123456789abcdefghijklmn\n")
        );
        assert_eq!(
            t.last_output(5).as_deref(),
            Some("klmn\n"),
            "its end, within the bound"
        );
        assert_eq!(t.screen_text(1 << 20), "one\n0123456789abcdefghijklmn\n$\n");
        // The blank rows below what shows are left out, but not one painted in a colour.
        let mut t = ServerTerminal::new(24, 20, 0).expect("emulator");
        t.process(b"$ ls\r\none\r\n\r\n$ ");
        assert_eq!(t.screen_text(1 << 20), "$ ls\none\n\n$\n");
        t.process(b"\x1b[6;1H\x1b[44m\x1b[K\x1b[0m");
        assert_eq!(t.screen_text(1 << 20), "$ ls\none\n\n$\n\n\n");
        // Scrolled out of a history that keeps nothing: gone.
        let mut t = ServerTerminal::new(2, 20, 0).expect("emulator");
        t.process(b"\x1b]133;C\x07a\r\nb\r\nc\r\n\x1b]133;D;0\x07");
        assert_eq!(t.last_output(1 << 20), None);
    }

    #[test]
    fn answers_reports_and_queries() {
        let mut t = ServerTerminal::new(24, 80, 0).expect("emulator");
        for (asked, answer) in [
            // DSR and DECXCPR at row 5, column 3, 1-indexed.
            (&b"\x1b[5;3H\x1b[6n"[..], &b"\x1b[5;3R"[..]),
            (b"\x1b[?6n", b"\x1b[?5;3R"),
            // DECRQM: reset, set, unknown.
            (
                b"\x1b[?2004$p\x1b[?2004h\x1b[?2004$p\x1b[?4242$p",
                b"\x1b[?2004;2$y\x1b[?2004;1$y\x1b[?4242;0$y",
            ),
            // Primary DA: level 2, with selective erase, horizontal scrolling, ANSI colour and
            // rectangular editing.
            (b"\x1b[c", b"\x1b[?62;6;21;22;28c"),
        ] {
            t.process(asked);
            assert_eq!(t.take_host_replies(), answer, "{asked:?}");
        }
        assert_eq!(t.take_host_replies(), b"", "drained");
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
    fn keys_mouse_and_focus_reach_a_program_as_it_asked_from_any_terminal() {
        // The user's terminal reports in SGR: a press at row 5, column 10, and its release.
        let click = &b"\x1b[<0;10;5M\x1b[<0;10;5m"[..];
        // A drag: motion with a button held, in 1002 and 1003 but not 1000; a hover, motion with
        // none, in 1003 alone.
        let (drag, hover) = (&b"\x1b[<32;11;5M"[..], &b"\x1b[<35;11;5M"[..]);
        let (sgr_1000, sgr_1002) = (
            &b"\x1b[?1000h\x1b[?1006h"[..],
            &b"\x1b[?1002h\x1b[?1006h"[..],
        );
        for (mode, sent, gets) in [
            // Legacy bytes back to a legacy program, cursor keys in its cursor mode.
            (&b""[..], &b"ls\r\x1b[A\x01"[..], &b"ls\r\x1b[A\x01"[..]),
            (b"\x1b[?1h", b"\x1b[A\x1bOB", b"\x1bOA\x1bOB"),
            // A program that pushed kitty's disambiguate gets kitty's keys, from a legacy
            // terminal: Ctrl-A and Escape are escapes, text stays text.
            (b"\x1b[>1u", b"a\x01", b"a\x1b[97;5u"),
            (b"\x1b[>1u", b"\x1b", b"\x1b[27u"),
            // And from a kitty terminal, which tells Ctrl-I from Tab.
            (b"\x1b[>1u", b"\x1b[105;5u\t", b"\x1b[105;5u\t"),
            // A legacy program gets a kitty terminal's keys as legacy bytes.
            (b"", b"\x1b[105;5u\x1b[1;5C", b"\t\x1b[1;5C"),
            // xterm's modifyOtherKeys 2.
            (b"\x1b[>4;2m", b"\x01", b"\x1b[27;5;97~"),
            // A pop restores the legacy keys.
            (b"\x1b[>1u\x1b[<u", b"\x01", b"\x01"),
            // Focus, only to a program that asked.
            (b"", b"\x1b[I\x1b[O", b""),
            (b"\x1b[?1004h", b"\x1b[I\x1b[O", b"\x1b[I\x1b[O"),
            (b"\x1b[?1004h\x1b[?1004l", b"\x1b[I", b""),
            // The mouse.
            (b"", click, b""),
            (b"\x1b[?9h", click, b"\x1b[M *%"),
            (b"\x1b[?1000h", click, b"\x1b[M *%\x1b[M#*%"),
            (sgr_1000, click, click),
            (
                b"\x1b[?1000h\x1b[?1005h",
                b"\x1b[<0;100;5M",
                "\x1b[M \u{84}%".as_bytes(),
            ),
            (sgr_1000, drag, b""),
            (sgr_1002, drag, drag),
            (sgr_1002, hover, b""),
            (b"\x1b[?1003h\x1b[?1006h", hover, hover),
            // The wheel.
            (sgr_1000, b"\x1b[<65;3;4M", b"\x1b[<65;3;4M"),
            // Past 223 the default encoding carries a 0 byte, as xterm 411 sends it.
            (b"\x1b[?1000h", b"\x1b[<0;224;1M", b"\x1b[M \0!"),
            (b"\x1b[?1000h", b"\x1b[<0;223;1M", b"\x1b[M \xff!"),
        ] {
            assert_eq!(program_gets(mode, sent), gets, "{mode:?} {sent:?}");
        }
    }

    #[test]
    fn a_paste_cannot_end_its_bracket_and_goes_plain_to_a_program_without_one() {
        let mut t = ServerTerminal::new(4, 20, 0).expect("emulator");
        t.process(b"\x1b[?2004h");
        let paste = |text: &str| InputEvent::Paste(text.to_owned());
        let mut out = Vec::new();
        t.encode_input(
            &[paste("a\x1b[201~b\x1b[20\x1b[201~1~cd\u{9b}201~")],
            &mut out,
        );
        assert_eq!(out, b"\x1b[200~abcd\x1b[201~");
        // Unbracketed: the text as pasted, each LF as CR, as xterm 411 sends a paste.
        t.process(b"\x1b[?2004l");
        out.clear();
        t.encode_input(&[paste("a\nb")], &mut out);
        assert_eq!(out, b"a\rb");
        // A paste is whole: what follows it is never inside its bracket.
        t.process(b"\x1b[?2004h");
        out.clear();
        let key = InputEvent::Key(
            fux_vt::keys::Keystroke::from(fux_vt::keys::KeyPress::plain(fux_vt::keys::Key::Char(
                'k',
            )))
            .into(),
        );
        t.encode_input(&[paste("a"), key], &mut out);
        assert_eq!(out, b"\x1b[200~a\x1b[201~k");
    }

    #[test]
    fn colour_queries_are_answered_from_the_users_terminal() {
        let mut t = ServerTerminal::new(4, 20, 0).expect("emulator");
        // Before any client said them, unanswered, as a terminal that does not know.
        t.process(b"\x1b]11;?\x07\x1b]10;?\x1b\\\x1b[?996n");
        assert_eq!(t.take_host_replies(), b"");
        assert_eq!(
            t.set_colours(&WireColours {
                foreground: Some([0xdd, 0xdd, 0xdd]),
                background: Some([0x1e, 0x1e, 0x20]),
                palette: [Some([0, 0, 0]); crate::events::PALETTE],
                scheme: Some(crate::events::WireScheme::Dark),
            }),
            b"",
            "no program subscribed"
        );
        // With the terminator the program used.
        t.process(b"\x1b]11;?\x07\x1b]10;?\x1b\\\x1b[?996n");
        assert_eq!(
            t.take_host_replies(),
            b"\x1b]11;rgb:1e1e/1e1e/2020\x07\x1b]10;rgb:dddd/dddd/dddd\x1b\\\x1b[?997;1n"
        );
        // A colour the program set wins: fux-vt answers it.
        t.process(b"\x1b]11;rgb:ff/ff/ff\x07\x1b]11;?\x07");
        assert_eq!(t.take_host_replies(), b"\x1b]11;rgb:ffff/ffff/ffff\x07");
        // A reattach from a light terminal: a program that subscribed (mode 2031) hears of it.
        t.process(b"\x1b[?2031h");
        let report = t.set_colours(&WireColours {
            background: Some([0xff, 0xff, 0xff]),
            scheme: Some(crate::events::WireScheme::Light),
            ..WireColours::default()
        });
        assert_eq!(report, b"\x1b[?997;2n");
        t.process(b"\x1b]110;?\x07\x1b]10;?\x07");
        assert_eq!(t.take_host_replies(), b"", "this client said no foreground");
    }

    #[test]
    fn palette_queries_are_answered_from_the_users_terminal() {
        let mut t = ServerTerminal::new(4, 20, 0).expect("emulator");
        // No client told its colours (`--no-colours`): xterm's defaults, as before.
        t.process(b"\x1b]4;1;?\x07");
        assert_eq!(t.take_host_replies(), b"\x1b]4;1;rgb:cdcd/0000/0000\x07");
        let mut palette = [None; crate::events::PALETTE];
        palette[1] = Some([0xbf, 0x61, 0x6a]);
        palette[2] = Some([0xa3, 0xbe, 0x8c]);
        t.set_colours(&WireColours {
            palette,
            ..WireColours::default()
        });
        // Entries the client gave, with the program's terminator; others xterm's.
        t.process(b"\x1b]4;1;?;2;?;3;?\x1b\\\x1b]4;200;?\x07");
        assert_eq!(
            t.take_host_replies(),
            b"\x1b]4;1;rgb:bfbf/6161/6a6a\x1b\\\x1b]4;2;rgb:a3a3/bebe/8c8c\x1b\\\
              \x1b]4;3;rgb:cdcd/cdcd/0000\x1b\\\x1b]4;200;rgb:ffff/0000/d7d7\x07"
        );
        // A colour the program set wins, and its reset brings the user's back.
        t.process(b"\x1b]4;1;#123456\x07\x1b]4;1;?\x07\x1b]104;1\x07\x1b]4;1;?\x07");
        assert_eq!(
            t.take_host_replies(),
            b"\x1b]4;1;rgb:1212/3434/5656\x07\x1b]4;1;rgb:bfbf/6161/6a6a\x07"
        );
        // A reattach from another terminal replaces the palette whole: an entry it did not
        // give goes back to xterm's.
        let mut palette = [None; crate::events::PALETTE];
        palette[2] = Some([0, 0, 0]);
        t.set_colours(&WireColours {
            palette,
            ..WireColours::default()
        });
        t.process(b"\x1b]4;1;?;2;?\x07");
        assert_eq!(
            t.take_host_replies(),
            b"\x1b]4;1;rgb:cdcd/0000/0000\x07\x1b]4;2;rgb:0000/0000/0000\x07"
        );
        // Nothing drawn changes: no row is in the palette's colours.
        assert!(!t.live().colors_changed());
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
        let contents = terminal.screen_text(1 << 20);
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
        assert!(terminal.screen_text(1 << 20).contains("ok"));
    }

    /// The bytes a program that wrote `setup` gets for `events`, as the client decoded them from
    /// what the user's terminal sent (`sent`).
    fn program_gets(setup: &[u8], sent: &[u8]) -> Vec<u8> {
        let mut t = ServerTerminal::new(24, 300, 0).expect("emulator");
        t.process(setup);
        let mut inputs = Vec::new();
        let mut decoder = fux_vt::keys::decode::Decoder::default();
        decoder.bytes(sent, &mut inputs);
        decoder.timeout(&mut inputs);
        let events: Vec<InputEvent> = inputs
            .into_iter()
            .filter_map(InputEvent::from_input)
            .collect();
        let mut out = Vec::new();
        t.encode_input(&events, &mut out);
        out
    }
}
