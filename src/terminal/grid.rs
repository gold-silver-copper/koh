//! The synced cell grid: what the client renders and the predictor reads.
//!
//! The server builds a [`Grid`] from its live `fux_vt::Screen`; the client only ever
//! reconstructs one from [`ScreenDiff`](super::ScreenDiff) rows. No terminal parser runs on the
//! client, so server-controlled bytes never reach one there.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use fux_vt::{Cell, MouseProtocolEncoding, MouseProtocolMode, RowId};

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

/// One row of a [`Grid`]: its cells, shared by every screen that holds the row unchanged, and
/// whether it soft-wraps into the next.
#[derive(Clone, Debug)]
struct Row {
    cells: Arc<[Cell]>,
    wrapped: bool,
}

impl Row {
    /// Whether `self` and `other` share one allocation of cells.
    fn shares(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.cells, &other.cells)
    }
}

impl PartialEq for Row {
    fn eq(&self, other: &Self) -> bool {
        self.wrapped == other.wrapped && (self.shares(other) || self.cells == other.cells)
    }
}

impl Eq for Row {}

/// The rows of the last snapshot, by fux-vt row id: a row whose cells are unchanged is shared
/// with the next snapshot, wherever it moved, instead of copied.
pub(super) type RowCache = HashMap<RowId, Arc<[Cell]>>;

/// A fixed-size screen of `fux_vt::Cell`s with a cursor, per-row soft-wrap flags and modes.
///
/// Always exactly `rows` rows of exactly `cols` cells. A row's cells are shared, not copied,
/// between screens that hold it unchanged: snapshots of the server's emulator, and a client
/// screen and the base it was diffed from. The cursor column may equal `cols` while an autowrap
/// is pending (fux-vt's parked cursor).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grid {
    rows: u16,
    cols: u16,
    lines: Vec<Row>,
    cursor: (u16, u16),
    modes: Modes,
}

impl Grid {
    /// A blank grid (default cells, cursor home, default modes). Every row shares one allocation.
    pub fn blank(rows: u16, cols: u16) -> Self {
        let blank = Row {
            cells: vec![Cell::default(); usize::from(cols)].into(),
            wrapped: false,
        };
        Self {
            rows,
            cols,
            lines: vec![blank; usize::from(rows)],
            cursor: (0, 0),
            modes: Modes::default(),
        }
    }

    /// Copy the live (non-history) rows, cursor and modes out of a fux-vt screen. A row `cache`
    /// holds unchanged since the last snapshot is shared rather than copied; `cache` is left
    /// holding this snapshot's rows.
    pub(super) fn of(screen: &fux_vt::Screen, cache: &mut RowCache) -> Self {
        let (rows, cols) = screen.size();
        let mut grid = Self::blank(rows, cols);
        let window = screen.window(0, rows, cols);
        let mut next = RowCache::with_capacity(usize::from(rows));
        for (row, line) in (0..rows).zip(grid.lines.iter_mut()) {
            let Some(live) = window.row(row) else {
                continue;
            };
            let cells = match cache.get(&live.id) {
                Some(cells) if **cells == *live.cells => Arc::clone(cells),
                // Live rows are exactly `cols` wide; copy what exists and leave any shortfall blank.
                _ => {
                    let mut cells = line.cells.to_vec();
                    for (d, s) in cells.iter_mut().zip(live.cells) {
                        *d = *s;
                    }
                    cells.into()
                }
            };
            next.insert(live.id, Arc::clone(&cells));
            *line = Row {
                cells,
                wrapped: live.wrapped,
            };
        }
        *cache = next;
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
        self.lines.get(usize::from(row)).map(|line| &*line.cells)
    }

    /// Whether `row` soft-wraps into the next one.
    pub fn row_wrapped(&self, row: u16) -> bool {
        self.lines
            .get(usize::from(row))
            .is_some_and(|line| line.wrapped)
    }

    /// Whether `row` is the same in `self` and `other`: the same cells and wrap flag. Rows that
    /// share their cells compare without reading them.
    pub(super) fn row_eq(&self, other: &Self, row: u16) -> bool {
        let row = usize::from(row);
        self.lines.get(row) == other.lines.get(row)
    }

    /// Whether `row` shares its cells with `other`'s, rather than holding a copy.
    pub fn row_shared(&self, other: &Self, row: u16) -> bool {
        let row = usize::from(row);
        match (self.lines.get(row), other.lines.get(row)) {
            (Some(line), Some(other)) => line.shares(other),
            _ => false,
        }
    }

    /// Replace `row` with `cells`, which must be exactly `cols` long. Out of bounds or a wrong
    /// length changes nothing.
    pub(super) fn set_row(&mut self, row: u16, cells: Arc<[Cell]>, wrapped: bool) {
        if cells.len() != usize::from(self.cols) {
            return;
        }
        if let Some(line) = self.lines.get_mut(usize::from(row)) {
            *line = Row { cells, wrapped };
        }
    }

    /// The cells the rows of `grids` hold, each allocation counted once however many rows and
    /// grids share it: what those grids cost in memory together.
    pub fn distinct_cells<'a>(grids: impl IntoIterator<Item = &'a Self>) -> usize {
        let mut seen: HashSet<*const Cell> = HashSet::new();
        let mut cells = 0_usize;
        for line in grids.into_iter().flat_map(|grid| &grid.lines) {
            if seen.insert(Arc::as_ptr(&line.cells).cast::<Cell>()) {
                cells = cells.saturating_add(line.cells.len());
            }
        }
        cells
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
