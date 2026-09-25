//! The synced cell grid: what the client renders and the predictor reads.
//!
//! The server builds a [`Grid`] from its live `fux_vt::Screen`; the client only ever
//! reconstructs one from [`ScreenDiff`](super::ScreenDiff) rows. No terminal parser runs on the
//! client, so server-controlled bytes never reach one there.

use fux_vt::{Cell, MouseProtocolEncoding, MouseProtocolMode};

use crate::predict::{CellView, ScreenView};

/// The terminal modes the client mirrors onto the real terminal (or draws with).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Modes {
    pub hide_cursor: bool,
    pub application_cursor: bool,
    pub application_keypad: bool,
    pub bracketed_paste: bool,
    pub mouse_mode: MouseProtocolMode,
    pub mouse_encoding: MouseProtocolEncoding,
}

impl Modes {
    fn of(screen: &fux_vt::Screen) -> Self {
        Self {
            hide_cursor: screen.hide_cursor(),
            application_cursor: screen.application_cursor(),
            application_keypad: screen.application_keypad(),
            bracketed_paste: screen.bracketed_paste(),
            mouse_mode: screen.mouse_protocol_mode(),
            mouse_encoding: screen.mouse_protocol_encoding(),
        }
    }
}

/// A fixed-size screen of `fux_vt::Cell`s with a cursor, per-row soft-wrap flags and modes.
///
/// Row-major, always exactly `rows × cols` cells. The cursor column may equal `cols` while an
/// autowrap is pending (fux-vt's parked cursor).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grid {
    rows: u16,
    cols: u16,
    cells: Vec<Cell>,
    wrapped: Vec<bool>,
    cursor: (u16, u16),
    modes: Modes,
}

impl Grid {
    /// A blank grid (default cells, cursor home, default modes).
    pub fn blank(rows: u16, cols: u16) -> Self {
        Self {
            rows,
            cols,
            // `repeat` sizes the buffer as exactly `rows × cols` cells.
            cells: vec![Cell::default(); usize::from(cols)].repeat(usize::from(rows)),
            wrapped: vec![false; usize::from(rows)],
            cursor: (0, 0),
            modes: Modes::default(),
        }
    }

    /// Copy the live (non-history) rows, cursor and modes out of a fux-vt screen.
    pub fn of(screen: &fux_vt::Screen) -> Self {
        let (rows, cols) = screen.size();
        let mut grid = Self::blank(rows, cols);
        let window = screen.window(0, rows, cols);
        for row in 0..rows {
            if let (Some(live), Some(dst)) = (window.row(row), grid.row_mut(row)) {
                // Live rows are exactly `cols` wide; copy what exists and leave any shortfall blank.
                for (d, s) in dst.iter_mut().zip(live.cells) {
                    *d = *s;
                }
                if let Some(w) = grid.wrapped.get_mut(usize::from(row)) {
                    *w = live.wrapped;
                }
            }
        }
        grid.cursor = screen.cursor_position();
        grid.modes = Modes::of(screen);
        grid
    }

    /// `(rows, cols)`.
    pub const fn size(&self) -> (u16, u16) {
        (self.rows, self.cols)
    }

    /// The cell at `(row, col)`, or `None` out of bounds.
    pub fn cell(&self, row: u16, col: u16) -> Option<&Cell> {
        self.row(row)?.get(usize::from(col))
    }

    /// One row's cells, or `None` out of bounds.
    pub fn row(&self, row: u16) -> Option<&[Cell]> {
        let start = self.row_start(row)?;
        self.cells.get(start..)?.get(..usize::from(self.cols))
    }

    pub(super) fn row_mut(&mut self, row: u16) -> Option<&mut [Cell]> {
        let start = self.row_start(row)?;
        self.cells.get_mut(start..)?.get_mut(..usize::from(self.cols))
    }

    /// Index of `row`'s first cell, or `None` out of bounds. `row < rows`, so the product is at
    /// most `rows × cols`, the length of `cells`, and cannot overflow.
    fn row_start(&self, row: u16) -> Option<usize> {
        if row >= self.rows {
            return None;
        }
        usize::from(row).checked_mul(usize::from(self.cols))
    }

    /// Whether `row` soft-wraps into the next one.
    pub fn row_wrapped(&self, row: u16) -> bool {
        self.wrapped.get(usize::from(row)).copied().unwrap_or(false)
    }

    pub(super) fn set_row_wrapped(&mut self, row: u16, wrapped: bool) {
        if let Some(w) = self.wrapped.get_mut(usize::from(row)) {
            *w = wrapped;
        }
    }

    /// The cursor as `(row, col)`, 0-indexed; `col` may equal `cols` while a wrap is pending.
    pub const fn cursor_position(&self) -> (u16, u16) {
        self.cursor
    }

    pub(super) fn set_cursor(&mut self, cursor: (u16, u16)) {
        self.cursor = cursor;
    }

    /// Whether the remote app hid the cursor.
    pub const fn hide_cursor(&self) -> bool {
        self.modes.hide_cursor
    }

    pub const fn modes(&self) -> Modes {
        self.modes
    }

    pub(super) fn set_modes(&mut self, modes: Modes) {
        self.modes = modes;
    }

    /// The screen as text: each row with trailing blanks trimmed, rows joined by `\n` except
    /// where a row soft-wraps into the next, trailing empty rows dropped.
    pub fn contents(&self) -> String {
        let mut out = String::new();
        for row in 0..self.rows {
            let line: String = self
                .row(row)
                .unwrap_or_default()
                .iter()
                .filter(|c| !c.is_wide_continuation())
                .map(|c| if c.has_contents() { c.contents() } else { " " })
                .collect();
            if self.row_wrapped(row) {
                out.push_str(&line);
            } else {
                out.push_str(line.trim_end());
                out.push('\n');
            }
        }
        let trimmed = out.trim_end_matches('\n').len();
        out.truncate(trimmed);
        out
    }
}

impl ScreenView for Grid {
    fn size(&self) -> (u16, u16) {
        Self::size(self)
    }
    fn cursor_position(&self) -> (u16, u16) {
        Self::cursor_position(self)
    }
    fn cell(&self, row: u16, col: u16) -> Option<CellView<'_>> {
        Self::cell(self, row, col).map(|c| CellView {
            contents: if c.has_contents() { c.contents() } else { "" },
            fg: c.fgcolor(),
            bg: c.bgcolor(),
        })
    }
}
