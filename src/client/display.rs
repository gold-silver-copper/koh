//! What `koh connect` writes to the user's terminal.
//!
//! The program's output as the server relays it, filtered once more here ([`crate::stream`]), the
//! shell's marks and the state reports with the terminal's own nonce, and over it all an overlay,
//! painted and taken back: the predicted echo of what was typed, and the status line.
//!
//! The client keeps a mirror of the terminal, a fux-vt parser fed what the terminal is fed, which
//! the predictor reads and which says what is under the overlay. Before anything is written, the
//! overlay is taken back (the cells it covered painted again from the mirror, the cursor and the
//! pen put back), so the terminal is always where the program's output left it. The overlay is
//! painted only where that can be done: on the primary screen, the cursor not waiting to wrap,
//! no origin or insert mode, no link open, no synchronized frame under way, and between two
//! sequences.

use std::io::{self, Write as _};

use fux_vt::{Attributes, Mode, SgrForm};

use super::backend::KohBackend;
use crate::predict::{Overlay, PredictionEngine};
use crate::stream::{Filter, Marks, Piece, Policy};
use crate::terminal::{Activity, Size};

/// The overlay as painted: the cells it covers, the status line's row if it was painted, and the
/// bytes that painted it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Painted {
    cells: Vec<(u16, u16)>,
    status: Option<u16>,
    bytes: Vec<u8>,
}

/// The user's terminal as the client writes to it.
pub struct Display {
    filter: Filter,
    mirror: fux_vt::Parser,
    pub predictor: PredictionEngine,
    /// What the overlay covers now, if it is painted.
    painted: Option<Painted>,
    /// The status line, if one is shown.
    status: Option<&'static str>,
    /// The last state report, written again after each mark: a terminal forgets one at a mark.
    report: Option<Activity>,
    /// Whether the terminal's pen and modes are the program's (not reset by `leave`).
    entered: bool,
    /// When the cursor last went to another row (or the screen scrolled under it): a key typed
    /// soon after, at a fresh prompt, waits for its echo, as the modes may not be known yet.
    pub new_row_at: Option<std::time::Instant>,
}

/// The mirror's options: what the terminal does that the overlay depends on.
const MIRROR: fux_vt::Options = fux_vt::Options::new()
    .with(fux_vt::Feature::Hyperlinks)
    .with(fux_vt::Feature::KittyKeyboard);

fn mirror(size: Size) -> io::Result<fux_vt::Parser> {
    fux_vt::Parser::with_options(crate::terminal::host_size(size), 0, MIRROR)
        .map_err(io::Error::other)
}

impl Display {
    /// A display for a terminal of `size`, the clipboard (OSC 52) and links (OSC 8) let through
    /// if allowed.
    pub fn new(size: Size, clipboard: bool, links: bool) -> io::Result<Self> {
        Ok(Self {
            filter: Filter::new(Policy {
                marks: Marks::Drop,
                clipboard,
                links,
            }),
            mirror: mirror(size)?,
            predictor: PredictionEngine::default(),
            painted: None,
            status: None,
            report: None,
            entered: false,
            new_row_at: None,
        })
    }

    /// A new epoch begins, its redraw next: the terminal is reset by it, so the mirror is too.
    pub fn new_epoch(&mut self, size: Size) -> io::Result<()> {
        self.filter = Filter::new(self.filter.policy().clone());
        self.mirror = mirror(size)?;
        self.predictor = self.predictor.reattached();
        self.painted = None;
        self.entered = true;
        Ok(())
    }

    /// The terminal is now `size`.
    pub fn resize(&mut self, size: Size) {
        let size = crate::terminal::host_size(size);
        let _ = self.mirror.resize(size);
        self.predictor.reset();
        self.painted = None;
    }

    /// Write the program's `output`, as the filter passes it.
    pub fn output(&mut self, backend: &mut impl KohBackend, output: &[u8]) -> io::Result<()> {
        let mut out = Vec::new();
        // Marks come apart, never in the output.
        self.filter.feed(output, &mut |piece| {
            if let Piece::Out(bytes) = piece {
                if out.is_empty() {
                    out = bytes;
                } else {
                    out.extend_from_slice(&bytes);
                }
            }
        });
        if out.is_empty() {
            return Ok(());
        }
        self.unpaint(backend)?;
        backend.write_bytes(&out)?;
        let row = |screen: &fux_vt::Screen| {
            (
                screen.cursor_position().0,
                screen.rows().next().map(|r| r.id()),
            )
        };
        let before = row(self.mirror.screen());
        if let Err(error) = self.mirror.process(&out) {
            tracing::debug!(%error, "the mirror of the terminal refused output");
        }
        if row(self.mirror.screen()) != before {
            self.new_row_at = Some(std::time::Instant::now());
        }
        self.predictor.cull(self.mirror.screen());
        Ok(())
    }

    /// Write the shell's mark, with the terminal's nonce, where the program's output left the
    /// cursor; then the last report again.
    pub fn mark(&mut self, backend: &mut impl KohBackend, mark: &[u8]) -> io::Result<()> {
        self.unpaint(backend)?;
        backend.mark(format_args!("{}", String::from_utf8_lossy(mark)))?;
        if let Some(report) = self.report {
            backend.mark(format_args!("S;activity={}", report.name()))?;
        }
        Ok(())
    }

    /// Report what the remote program is doing.
    pub fn report(&mut self, backend: &mut impl KohBackend, activity: Activity) -> io::Result<()> {
        self.report = Some(activity);
        backend.mark(format_args!("S;activity={}", activity.name()))
    }

    /// Report that the remote program ended having read every key sent it (`OSC 133 ; S ;
    /// activity=ended`): a terminal driving koh knows the last keys reached it, though no report
    /// of it reading again came.
    pub fn ended(&mut self, backend: &mut impl KohBackend) -> io::Result<()> {
        self.unpaint(backend)?;
        backend.mark(format_args!("S;activity=ended"))
    }

    /// Grade the predictions against the terminal as it is.
    pub fn reconcile(&mut self) {
        self.predictor.cull(self.mirror.screen());
    }

    /// Predict what typing `press` does.
    pub fn predict_key(&mut self, press: fux_vt::keys::KeyPress) {
        self.predictor.new_user_key(press, self.mirror.screen());
    }

    /// Typed input the predictor does not model: a new epoch, no guess.
    pub fn predict_other(&mut self) {
        self.predictor.new_user_other(self.mirror.screen());
    }

    /// Show `status` on the status line, or none.
    pub const fn set_status(&mut self, status: Option<&'static str>) {
        self.status = status;
    }

    /// Whether the overlay can be painted on the terminal as the mirror holds it.
    fn paintable(&self) -> bool {
        let screen = self.mirror.screen();
        !screen.mode(Mode::AlternateScreen)
            && !screen.mode(Mode::Origin)
            && !screen.mode(Mode::Insert)
            && !screen.mode(Mode::SynchronizedOutput)
            && !screen.pending_wrap()
            && screen.hyperlink().is_none()
            && self.filter.between()
    }

    /// Paint the overlay, if there is one to paint and it can be: the predictions, the status
    /// line, and the cursor where the predictions put it. An overlay painted as it is stays.
    pub fn paint(&mut self, backend: &mut impl KohBackend) -> io::Result<()> {
        let overlay: Overlay = self.predictor.overlay();
        if (overlay.is_empty() && self.status.is_none()) || !self.paintable() {
            return self.unpaint(backend);
        }
        let screen = self.mirror.screen();
        let (rows, cols) = screen.size().into();
        let mut out = b"\x1b[?2026h".to_vec();
        let mut cells = Vec::new();
        let mut status_row = None;
        let mut pen = None;
        for ((row, col), cell) in overlay.cells() {
            if cell.covered() || row >= rows || col >= cols {
                continue;
            }
            cup(&mut out, row, col);
            sgr(&mut out, &mut pen, cell.attributes());
            let glyph = if cell.text().is_empty() {
                " "
            } else {
                cell.text()
            };
            out.extend_from_slice(glyph.as_bytes());
            cells.push((row, col));
            if unicode_width::UnicodeWidthStr::width(glyph) > 1 {
                cells.push((row, col.saturating_add(1)));
            }
        }
        if let Some(status) = self.status {
            let row = rows.saturating_sub(1);
            cup(&mut out, row, 0);
            let mut line: String = status.chars().take(usize::from(cols)).collect();
            while unicode_width::UnicodeWidthStr::width(line.as_str()) > usize::from(cols) {
                line.pop();
            }
            out.extend_from_slice(b"\x1b[0;7m\x1b[2K");
            out.extend_from_slice(line.as_bytes());
            status_row = Some(row);
        }
        let (row, col) = overlay.cursor().unwrap_or_else(|| screen.cursor_position());
        cup(
            &mut out,
            row.min(rows.saturating_sub(1)),
            col.min(cols.saturating_sub(1)),
        );
        out.extend_from_slice(b"\x1b[?2026l");
        if self.painted.as_ref().is_some_and(|p| p.bytes == out) {
            return Ok(());
        }
        self.unpaint(backend)?;
        backend.write_bytes(&out)?;
        let predicted: String = overlay.cells().map(|(_, cell)| cell.text()).collect();
        backend.overlay(&predicted, self.status);
        self.painted = Some(Painted {
            cells,
            status: status_row,
            bytes: out,
        });
        Ok(())
    }

    /// Take the overlay back: what it covered painted again from the mirror, the cursor and the
    /// pen put back.
    pub fn unpaint(&mut self, backend: &mut impl KohBackend) -> io::Result<()> {
        let Some(painted) = self.painted.take() else {
            return Ok(());
        };
        backend.overlay("", None);
        let screen = self.mirror.screen();
        let mut out = b"\x1b[?2026h".to_vec();
        let mut pen = None;
        let mut cells = painted.cells;
        if let Some(row) = painted.status {
            let (_, cols) = screen.size().into();
            cells.extend((0..cols).map(|col| (row, col)));
        }
        cells.sort_unstable();
        cells.dedup();
        for (row, col) in cells {
            // A wide glyph is painted from its first half.
            let (col, cell) = match screen.cell(row, col) {
                Some(cell) if cell.is_wide_continuation() => {
                    let left = col.saturating_sub(1);
                    match screen.cell(row, left) {
                        Some(wide) => (left, wide),
                        None => continue,
                    }
                }
                Some(cell) => (col, cell),
                None => continue,
            };
            cup(&mut out, row, col);
            sgr(&mut out, &mut pen, cell.attributes());
            let glyph = cell.contents();
            out.extend_from_slice(if glyph.is_empty() {
                b" "
            } else {
                glyph.as_bytes()
            });
        }
        let (row, col) = screen.cursor_position();
        cup(&mut out, row, col);
        out.extend_from_slice(b"\x1b[0");
        screen
            .attributes()
            .write_sgr(&mut out, SgrForm::Paint { styles: true });
        out.push(b'm');
        out.extend_from_slice(b"\x1b[?2026l");
        backend.write_bytes(&out)
    }

    /// Leave the terminal as the user's shell expects it: the overlay taken back, and every mode
    /// the program set that the mirror says is set put back, the cursor below what was shown.
    pub fn leave(&mut self, backend: &mut impl KohBackend) -> io::Result<()> {
        self.unpaint(backend)?;
        if !self.entered {
            return Ok(());
        }
        self.entered = false;
        let screen = self.mirror.screen();
        let kitty = screen.kitty_keyboard_flags() != 0;
        let mut out = Vec::new();
        if screen.mode(Mode::SynchronizedOutput) {
            out.extend_from_slice(b"\x1b[?2026l");
        }
        if screen.mode(Mode::AlternateScreen) {
            out.extend_from_slice(b"\x1b[?1049l");
        }
        if screen.hyperlink().is_some() {
            out.extend_from_slice(b"\x1b]8;;\x1b\\");
        }
        // Where the cursor is once the main screen is back: the margins' and origin mode's resets
        // below send it home, and it goes back there after them.
        if let Err(error) = self.mirror.process(&out) {
            tracing::debug!(%error, "the mirror of the terminal refused output");
        }
        let screen = self.mirror.screen();
        let (row, col) = screen.cursor_position();
        let blank = screen.cell(row, 0).is_none_or(|c| !c.has_contents());
        out.extend_from_slice(
            b"\x1b[0m\x1b[r\x1b[?69l\x1b[?6l\x1b[?7h\x1b[4l\x1b[?25h\x1b[?1l\x1b>\x1b[?9l\
              \x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1005l\x1b[?1006l\x1b[?1004l\x1b[?2004l\
              \x1b[?2031l\x1b[>4;0m",
        );
        cup(&mut out, row, col);
        // Every kitty keyboard mode the program pushed.
        if kitty {
            out.extend_from_slice(b"\x1b[<99u");
        }
        out.extend_from_slice(b"\x1b]104\x1b\\\x1b]110\x1b\\\x1b]111\x1b\\\x1b]112\x1b\\");
        backend.write_bytes(&out)?;
        // A fresh line, unless the cursor is at the start of an empty one.
        if col > 0 || !blank {
            backend.write_bytes(b"\r\n")?;
        }
        Ok(())
    }
}

/// `CUP` to `row`, `col`, 0-based.
fn cup(out: &mut Vec<u8>, row: u16, col: u16) {
    let _ = write!(
        out,
        "\x1b[{};{}H",
        u32::from(row).saturating_add(1),
        u32::from(col).saturating_add(1)
    );
}

/// Set `attributes` as the pen, unless `pen` says it is.
fn sgr(out: &mut Vec<u8>, pen: &mut Option<Attributes>, attributes: Attributes) {
    if *pen != Some(attributes) {
        out.extend_from_slice(b"\x1b[0");
        attributes.write_sgr(out, SgrForm::Paint { styles: true });
        out.push(b'm');
        *pen = Some(attributes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::backend::CaptureBackend;
    use crate::predict::TtyModes;
    use fux_vt::keys::{Key, KeyPress};

    /// What a terminal shows after `bytes`, as a fux-vt parser holds it: each row's text and the
    /// cursor.
    fn shown(rows: u16, cols: u16, bytes: &[u8]) -> (Vec<String>, (u16, u16)) {
        let size = fux_vt::Size::new(rows, cols).unwrap();
        let mut term = fux_vt::Parser::with_options(size, 0, MIRROR).unwrap();
        term.process(bytes).unwrap();
        let screen = term.screen();
        (
            screen
                .rows()
                .map(|r| r.cells_text().trim_end().to_owned())
                .collect(),
            screen.cursor_position(),
        )
    }

    #[test]
    fn a_prediction_shows_and_is_taken_back_before_the_programs_output() {
        let mut backend = CaptureBackend::default();
        let mut display = Display::new(Size::new(4, 20), true, true).unwrap();
        display.new_epoch(Size::new(4, 20)).unwrap();
        display.output(&mut backend, b"$ ").unwrap();
        // A line editor that echoes for itself, trusted.
        display.predictor.set_tty(Some(TtyModes {
            echo: false,
            line: false,
        }));
        display.predictor.confirm_for_tests();
        // Sent as input 1.
        display.predictor.set_local_frame_sent(0);
        display.predict_key(KeyPress::plain(Key::Char('l')));
        display.paint(&mut backend).unwrap();
        let after_paint = backend.written.clone();
        assert_eq!(
            shown(4, 20, &after_paint),
            (
                vec!["$ l".into(), String::new(), String::new(), String::new()],
                (0, 3)
            )
        );
        // The echo comes: the prediction goes first, and the terminal shows what the program
        // wrote, where it wrote it.
        display.output(&mut backend, b"ls\r\nfile\r\n$ ").unwrap();
        display.predictor.set_local_frame_late_acked(1);
        display.reconcile();
        display.paint(&mut backend).unwrap();
        let all = backend.written.clone();
        assert_eq!(
            shown(4, 20, &all),
            (
                vec!["$ ls".into(), "file".into(), "$".into(), String::new()],
                (2, 2)
            )
        );
    }

    #[test]
    fn the_status_line_covers_the_last_row_and_is_taken_back_whole() {
        let mut backend = CaptureBackend::default();
        let mut display = Display::new(Size::new(3, 10), true, true).unwrap();
        display.new_epoch(Size::new(3, 10)).unwrap();
        display
            .output(&mut backend, b"a\r\nb\r\ncdef\x1b[1;1H")
            .unwrap();
        display.set_status(Some("reconnecting"));
        display.paint(&mut backend).unwrap();
        assert_eq!(shown(3, 10, &backend.written).0[2], "reconnecti");
        display.set_status(None);
        display.paint(&mut backend).unwrap();
        assert_eq!(
            shown(3, 10, &backend.written),
            (vec!["a".into(), "b".into(), "cdef".into()], (0, 0))
        );
    }

    #[test]
    fn marks_carry_the_terminals_nonce_and_the_last_report_follows_each() {
        let mut backend = CaptureBackend::default();
        backend.nonce = crate::client::backend::MarkNonce::new("n1");
        let mut display = Display::new(Size::new(3, 10), true, true).unwrap();
        display.report(&mut backend, Activity::Reading).unwrap();
        display.mark(&mut backend, b"D;0").unwrap();
        assert_eq!(
            String::from_utf8_lossy(&backend.written),
            "\x1b]133;S;activity=reading;nonce=n1\x07\x1b]133;D;0;nonce=n1\x07\
             \x1b]133;S;activity=reading;nonce=n1\x07"
        );
        // Marks and questions in the output itself never reach the terminal.
        backend.written.clear();
        display
            .output(&mut backend, b"x\x1b]133;D;1\x07\x1b[6n\x1b]52;c;?\x07y")
            .unwrap();
        assert_eq!(backend.written, b"xy");
    }

    /// A program (or a hostile server) leaves nothing set in the user's terminal: what it set is
    /// put back when the client leaves.
    #[test]
    fn what_the_program_set_is_put_back_when_the_client_leaves() {
        let mut backend = CaptureBackend::default();
        let mut display = Display::new(Size::new(4, 20), true, true).unwrap();
        display.new_epoch(Size::new(4, 20)).unwrap();
        display
            .output(
                &mut backend,
                b"\x1b[?1049h\x1b[?1003h\x1b[?1006h\x1b[?2004h\x1b[?25l\x1b[?1h\x1b=\x1b[>5u\
                  \x1b]4;1;rgb:ff/00/00\x07\x1b]8;;https://x\x07\x1b[31;1mred",
            )
            .unwrap();
        display.leave(&mut backend).unwrap();
        let mut term =
            fux_vt::Parser::with_options(fux_vt::Size::new(4, 20).unwrap(), 0, MIRROR).unwrap();
        term.process(&backend.written).unwrap();
        let screen = term.screen();
        for mode in [
            Mode::AlternateScreen,
            Mode::BracketedPaste,
            Mode::ApplicationCursor,
            Mode::ApplicationKeypad,
        ] {
            assert!(!screen.mode(mode), "{mode:?} left set");
        }
        assert!(screen.mode(Mode::ShowCursor));
        assert_eq!(
            screen.mouse_protocol_mode(),
            fux_vt::MouseProtocolMode::None
        );
        assert_eq!(screen.kitty_keyboard_flags(), 0);
        assert!(screen.hyperlink().is_none());
        assert_eq!(screen.attributes(), Attributes::default());
        // The palette is put back too.
        assert!(backend.written.windows(7).any(|w| w == b"\x1b]104\x1b\\"));
    }

    /// Leaving puts the cursor back where the program left it, the margins reset (which sends it
    /// home), then on a fresh line: the user's prompt comes below the output, not over its top.
    #[test]
    fn leaving_resets_the_margins_and_keeps_the_cursor_below_the_output() {
        for program in [
            &b"one\r\ntwo\r\nthree"[..],
            b"\x1b[?1049h\x1b[2;3r\x1b[?6hfull",
        ] {
            let mut backend = CaptureBackend::default();
            let mut display = Display::new(Size::new(6, 20), true, true).unwrap();
            display.new_epoch(Size::new(6, 20)).unwrap();
            let before = b"one\r\ntwo\r\nthree";
            display.output(&mut backend, before).unwrap();
            if program != before {
                display.output(&mut backend, program).unwrap();
            }
            display.leave(&mut backend).unwrap();
            let (rows, cursor) = shown(6, 20, &backend.written);
            assert_eq!(rows[..3], ["one", "two", "three"], "{program:?}");
            assert_eq!(cursor, (3, 0), "{program:?}: {rows:?}");
        }
    }
}
