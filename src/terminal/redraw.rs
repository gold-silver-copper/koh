//! A session's screen, written for a terminal that shows nothing of it yet: what a client is
//! sent as it attaches, and again when it fell too far behind to be sent what it missed.
//!
//! From a terminal's reset state, it paints the primary screen (with as much history before it
//! as asked, as lines that scroll into the terminal's own scrollback), then the alternate screen
//! if it is shown, then puts back what the program set and what follows relies on: the scroll
//! region and margins, origin mode, the cursor and its shape, the pen and the open link, the input
//! modes, and the title. The rows that start a prompt are marked, and so is where the output of a
//! command still running began, if it is on the screen ([`Piece::Mark`]).
//!
//! What it cannot put back: the character sets, the tab stops, a cursor saved with DECSC and the
//! palette a program set (a program that relies on them shows right again once it redraws).

use std::io::Write as _;

use fux_vt::{Attributes, CellRef, Mode, MouseProtocolEncoding, MouseProtocolMode, SgrForm};
use unicode_width::UnicodeWidthChar as _;

use crate::stream::Piece;

/// What leaves a terminal as a fresh one shows a program: the primary screen, no margins, the
/// cursor shown and wrapping, no input mode a program set, the pen and the palette reset.
pub const RESET: &[u8] = b"\x1b[?2026l\x1b[?1049l\x1b[?47l\x1b[?1047l\x1b[r\x1b[?69l\x1b[?6l\
\x1b[?7h\x1b[4l\x1b[20l\x1b[?5l\x1b[?25h\x1b[?1l\x1b>\x1b[?9l\x1b[?1000l\x1b[?1001l\x1b[?1002l\x1b[?1003l\
\x1b[?1005l\x1b[?1006l\x1b[?1015l\x1b[?1016l\x1b[?1004l\x1b[?2004l\x1b[?2031l\x1b[=0;1u\x1b[>4;0m\x1b]8;;\x1b\\\x1b[0m\
\x1b]104\x1b\\\x1b]110\x1b\\\x1b]111\x1b\\\x1b]112\x1b\\";

/// Whether every terminal takes `glyph` as as wide as fux-vt does: one character, not of
/// ambiguous width. After any other, where a terminal leaves the cursor is not known.
fn certain(glyph: &str) -> bool {
    let mut chars = glyph.chars();
    matches!((chars.next(), chars.next()), (Some(c), None) if c.width() == c.width_cjk())
}

/// Builds a redraw's pieces.
struct Painter {
    pieces: Vec<Piece>,
    out: Vec<u8>,
    /// The pen the terminal has.
    pen: Attributes,
    /// The link open on the terminal, as written.
    link: Option<Vec<u8>>,
}

impl Painter {
    fn mark(&mut self, mark: &[u8]) {
        if !self.out.is_empty() {
            self.pieces.push(Piece::Out(std::mem::take(&mut self.out)));
        }
        self.pieces.push(Piece::Mark(mark.to_vec()));
    }

    fn pen(&mut self, attributes: Attributes) {
        if attributes != self.pen {
            self.out.extend_from_slice(b"\x1b[0");
            attributes.write_sgr(&mut self.out, SgrForm::Paint { styles: true });
            self.out.push(b'm');
            self.pen = attributes;
        }
    }

    fn link(&mut self, link: Option<&fux_vt::Hyperlink>) {
        let want = link.map(|link| {
            let mut osc = b"\x1b]8;".to_vec();
            if let Some(id) = link.id() {
                osc.extend_from_slice(b"id=");
                osc.extend_from_slice(id.as_bytes());
            }
            osc.push(b';');
            osc.extend_from_slice(link.uri().as_bytes());
            osc.extend_from_slice(b"\x1b\\");
            osc
        });
        if want != self.link {
            match &want {
                Some(osc) => self.out.extend_from_slice(osc),
                None => self.out.extend_from_slice(b"\x1b]8;;\x1b\\"),
            }
            self.link = want;
        }
    }

    fn cup(&mut self, row: u16, col: u16) {
        let _ = write!(
            self.out,
            "\x1b[{};{}H",
            row.saturating_add(1),
            col.saturating_add(1)
        );
    }

    /// Paint `row`, `width` columns, from where the cursor is (`at`, the row's place on the
    /// terminal, for moves). Whether it ended with the cursor waiting to wrap at the last column.
    fn row(&mut self, row: &fux_vt::Row<'_>, width: u16, at: Option<u16>) -> bool {
        // The last column painted: blanks past it are left as the cleared terminal has them, but
        // a soft-wrapped row is painted whole, so the terminal wraps it softly too.
        let cells: Vec<CellRef<'_>> = row.cells().take(usize::from(width)).collect();
        let last = if row.wrapped() {
            cells.len()
        } else {
            cells
                .iter()
                .rposition(|cell| cell.has_contents() || cell.attributes() != Attributes::default())
                .map_or(0, |at| at.saturating_add(1))
        };
        let mut moved = false;
        let mut col: u16 = 0;
        // The glyph printed before, which a terminal joins the next one to if it continues its
        // cluster (a skin tone a program put in a cell of its own).
        let mut before = String::new();
        for (n, cell) in cells.iter().enumerate().take(last) {
            if cell.is_wide_continuation() {
                continue;
            }
            let here = u16::try_from(n).unwrap_or(u16::MAX);
            let glyph = cell.contents();
            let joins = glyph
                .chars()
                .next()
                .is_some_and(|c| !before.is_empty() && fux_vt::continues_cluster(&before, c));
            if moved || joins {
                if let Some(at) = at {
                    self.cup(at, here);
                }
            }
            self.pen(cell.attributes());
            self.link(row.link(n));
            glyph.clone_into(&mut before);
            if glyph.is_empty() {
                self.out.push(b' ');
            } else {
                self.out.extend_from_slice(glyph.as_bytes());
            }
            moved = !glyph.is_empty() && !certain(glyph);
            col = here.saturating_add(if cell.is_wide() { 2 } else { 1 });
        }
        self.link(None);
        col >= width
    }
}

/// What `screen` shows, written for a reset terminal of its size, with up to `history` rows of
/// what scrolled off before the screen, and the window `title`.
pub fn redraw(screen: &fux_vt::Screen, title: &str, history: usize) -> Vec<Piece> {
    let mut p = Painter {
        pieces: Vec::new(),
        out: Vec::new(),
        pen: Attributes::default(),
        link: None,
    };
    let size = screen.size();
    let (rows, cols) = (size.rows(), size.cols());
    p.out.extend_from_slice(RESET);
    p.out.extend_from_slice(b"\x1b[H\x1b[2J");
    // The primary screen and the history kept above it, as lines that scroll: the history goes
    // into the terminal's own scrollback.
    let main: Vec<fux_vt::Row<'_>> = screen.main_rows().collect();
    let shown = usize::from(rows);
    let from = main.len().saturating_sub(shown).saturating_sub(history);
    let lines = main.get(from..).unwrap_or_default();
    let alternate = screen.mode(Mode::AlternateScreen);
    let commands = screen.commands();
    for (n, row) in lines.iter().enumerate() {
        if row.starts_prompt() {
            p.mark(b"A");
        }
        // Moves within a row need its place, which only the screen's rows have.
        let on_screen = n.checked_sub(lines.len().saturating_sub(shown));
        let at = on_screen.and_then(|r| u16::try_from(r).ok());
        let filled = p.row(row, cols, at);
        if n.saturating_add(1) < lines.len() {
            // A soft wrap that filled its row wraps on its own, and the terminal keeps it soft.
            if !(row.wrapped() && filled) {
                p.pen(Attributes::default());
                p.out.extend_from_slice(b"\r\n");
            }
        }
    }
    // Where a command still running began its output: marked there, if the screen shows it.
    if let Some(start) = commands.output_start.filter(|_| !alternate) {
        let top = main.len().saturating_sub(shown);
        let place = screen
            .row_index(start.row)
            .and_then(|at| at.checked_sub(top))
            .and_then(|row| u16::try_from(row).ok());
        if let Some(row) = place {
            p.cup(row, start.col.min(cols.saturating_sub(1)));
            p.mark(b"C");
        }
    }
    if alternate {
        p.pen(Attributes::default());
        // `?1049 h` saves the cursor where it stands: where the program saved the primary
        // screen's, so its `?1049 l` puts it back there.
        let (row, col) = screen.main_saved_cursor();
        p.cup(row, col);
        p.out.extend_from_slice(b"\x1b[?1049h\x1b[H\x1b[2J");
        let mut wraps = false;
        for (row_at, row) in (0_u16..).zip(screen.alternate_rows()) {
            if !wraps {
                p.cup(row_at, 0);
            }
            wraps = p.row(&row, cols, Some(row_at)) && row.wrapped();
        }
    }
    let out = &mut p.out;
    // The margins, then origin mode, which homes the cursor; then the cursor.
    let (top, bottom) = screen.scroll_region();
    if (top, bottom) != (0, rows.saturating_sub(1)) {
        let _ = write!(
            out,
            "\x1b[{};{}r",
            top.saturating_add(1),
            bottom.saturating_add(1)
        );
    }
    if screen.mode(Mode::LeftRightMargins) {
        let (left, right) = screen.left_right_margins();
        let _ = write!(
            out,
            "\x1b[?69h\x1b[{};{}s",
            left.saturating_add(1),
            right.saturating_add(1)
        );
    }
    let flags = [
        (Mode::Origin, "?6"),
        (Mode::Insert, "4"),
        (Mode::NewLine, "20"),
        (Mode::ReverseVideo, "?5"),
        (Mode::ApplicationCursor, "?1"),
        (Mode::FocusReporting, "?1004"),
        (Mode::BracketedPaste, "?2004"),
        (Mode::ColorSchemeUpdates, "?2031"),
    ];
    for (mode, number) in flags {
        if screen.mode(mode) {
            let _ = write!(out, "\x1b[{number}h");
        }
    }
    if !screen.mode(Mode::Autowrap) {
        out.extend_from_slice(b"\x1b[?7l");
    }
    if screen.mode(Mode::ApplicationKeypad) {
        out.extend_from_slice(b"\x1b=");
    }
    let mouse = match screen.mouse_protocol_mode() {
        MouseProtocolMode::None => None,
        MouseProtocolMode::Press => Some("9"),
        MouseProtocolMode::PressRelease => Some("1000"),
        MouseProtocolMode::Highlight => Some("1001"),
        MouseProtocolMode::ButtonMotion => Some("1002"),
        MouseProtocolMode::AnyMotion => Some("1003"),
    };
    if let Some(mouse) = mouse {
        let _ = write!(out, "\x1b[?{mouse}h");
    }
    match screen.mouse_protocol_encoding() {
        MouseProtocolEncoding::Default => {}
        MouseProtocolEncoding::Utf8 => out.extend_from_slice(b"\x1b[?1005h"),
        MouseProtocolEncoding::Sgr => out.extend_from_slice(b"\x1b[?1006h"),
        MouseProtocolEncoding::Urxvt => out.extend_from_slice(b"\x1b[?1015h"),
        MouseProtocolEncoding::SgrPixels => out.extend_from_slice(b"\x1b[?1016h"),
    }
    let kitty = screen.kitty_keyboard_flags();
    if kitty != 0 {
        let _ = write!(out, "\x1b[>{kitty}u");
    }
    if let Some(level) = screen.modify_other_keys() {
        use fux_vt::keys::encode::OtherKeysLevel;
        let level = match level {
            OtherKeysLevel::Usual => 1,
            OtherKeysLevel::All => 2,
            OtherKeysLevel::Unmodified => 3,
        };
        let _ = write!(out, "\x1b[>4;{level}m");
    }
    let shape = screen.cursor_shape();
    if shape != fux_vt::CursorShape::Initial {
        let _ = write!(out, "\x1b[{} q", shape.number());
    }
    if !title.is_empty() {
        out.extend_from_slice(b"\x1b]2;");
        out.extend(title.bytes().filter(|b| !b.is_ascii_control()));
        out.extend_from_slice(b"\x1b\\");
    }
    // The cursor, waiting to wrap if it was: the glyph before it printed again leaves it so.
    let (row, col) = screen.cursor_position();
    let origin = if screen.mode(Mode::Origin) { top } else { 0 };
    let (left, _) = screen.left_right_margins();
    let left = if screen.mode(Mode::Origin) && screen.mode(Mode::LeftRightMargins) {
        left
    } else {
        0
    };
    let cup = |out: &mut Vec<u8>, row: u16, col: u16| {
        let _ = write!(
            out,
            "\x1b[{};{}H",
            row.saturating_sub(origin).saturating_add(1),
            col.saturating_sub(left).saturating_add(1)
        );
    };
    let last = screen.cell(row, col).filter(|cell| {
        screen.pending_wrap() && cell.has_contents() && !cell.is_wide_continuation()
    });
    match last {
        Some(cell) if certain(cell.contents()) => {
            cup(out, row, col);
            p.pen(cell.attributes());
            p.out.extend_from_slice(cell.contents().as_bytes());
        }
        Some(_) | None => cup(out, row, col),
    }
    p.pen(screen.attributes());
    if let Some((uri, id)) = screen.hyperlink() {
        let _ = write!(
            p.out,
            "\x1b]8;{};{uri}\x1b\\",
            id.map(|id| format!("id={id}")).unwrap_or_default()
        );
    }
    if !screen.mode(Mode::ShowCursor) {
        p.out.extend_from_slice(b"\x1b[?25l");
    }
    if !p.out.is_empty() {
        p.pieces.push(Piece::Out(p.out));
    }
    p.pieces
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What a terminal of `rows` x `cols` that saw `bytes` shows, as a fux-vt parser holds it.
    fn parser(rows: u16, cols: u16, bytes: &[u8]) -> fux_vt::Parser {
        let size = fux_vt::Size::new(rows, cols).unwrap();
        let mut parser =
            fux_vt::Parser::with_options(size, 1 << 20, crate::terminal::OPTIONS).unwrap();
        parser.process(bytes).unwrap();
        parser
    }

    /// The redraw's bytes, marks left out.
    fn bytes(pieces: &[Piece]) -> Vec<u8> {
        pieces
            .iter()
            .filter_map(|p| match p {
                Piece::Out(b) => Some(b.clone()),
                Piece::Mark(_) => None,
            })
            .flatten()
            .collect()
    }

    /// Each row's text and whether it wraps softly, and the cursor, as `screen` shows them.
    fn shown(screen: &fux_vt::Screen) -> (Vec<(String, bool)>, (u16, u16), bool) {
        let rows = screen.rows().skip(screen.history_len());
        (
            rows.map(|r| (r.cells_text().trim_end().to_owned(), r.wrapped()))
                .collect(),
            screen.cursor_position(),
            screen.pending_wrap(),
        )
    }

    #[test]
    fn a_redrawn_terminal_shows_what_the_program_drew_and_is_in_its_modes() {
        let cases: &[&[u8]] = &[
            b"$ ls\r\nfile\r\n\x1b[1;31mred\x1b[0m wide \xe4\xb8\xad end\r\n$ ",
            // The alternate screen, a scroll region, origin mode, a hidden cursor and the mouse.
            b"main\x1b[?1049h\x1b[2;5r\x1b[?6h\x1b[2;3Hin region\x1b[?25l\x1b[?1002h\x1b[?1006h",
            // A full row waiting to wrap, then a soft-wrapped line, then one that wrapped a wide
            // glyph and so ends blank.
            b"1234567890\r\nabcdefghijklmno\r\nabcdefghi\xe4\xb8\xad",
        ];
        for bytes_in in cases {
            let program = parser(6, 10, bytes_in);
            let pieces = redraw(program.screen(), "t", 0);
            let fresh = parser(6, 10, &bytes(&pieces));
            let (want, got) = (program.screen(), fresh.screen());
            assert_eq!(
                shown(got),
                shown(want),
                "{:?}",
                String::from_utf8_lossy(bytes_in)
            );
            for mode in [
                Mode::AlternateScreen,
                Mode::Origin,
                Mode::ShowCursor,
                Mode::Autowrap,
            ] {
                assert_eq!(got.mode(mode), want.mode(mode), "{mode:?}");
            }
            assert_eq!(got.scroll_region(), want.scroll_region());
            assert_eq!(got.mouse_protocol_mode(), want.mouse_protocol_mode());
            assert_eq!(got.attributes(), want.attributes());
            if want.mode(Mode::AlternateScreen) {
                let main = |s: &fux_vt::Screen| {
                    s.main_rows()
                        .map(|r| r.cells_text().trim_end().to_owned())
                        .collect::<Vec<_>>()
                };
                assert_eq!(main(got), main(want));
                // Where leaving the alternate screen puts the cursor back.
                assert_eq!(got.main_saved_cursor(), want.main_saved_cursor());
            }
        }
    }

    #[test]
    fn history_scrolls_into_the_terminal_and_prompts_are_marked() {
        let mut input = Vec::new();
        for n in 0..20 {
            input.extend_from_slice(format!("line {n}\r\n").as_bytes());
        }
        input.extend_from_slice(b"\x1b]133;A\x07$ ");
        let program = parser(4, 20, &input);
        let pieces = redraw(program.screen(), "", 5);
        let fresh = parser(4, 20, &bytes(&pieces));
        assert_eq!(shown(fresh.screen()), shown(program.screen()));
        let history: Vec<String> = fresh
            .screen()
            .rows()
            .take(fresh.screen().history_len())
            .map(|r| r.cells_text().trim_end().to_owned())
            .collect();
        assert_eq!(history.last().map(String::as_str), Some("line 16"));
        assert_eq!(history.len(), 5);
        assert_eq!(
            pieces
                .iter()
                .filter(|p| **p == Piece::Mark(b"A".to_vec()))
                .count(),
            1
        );
    }
}
