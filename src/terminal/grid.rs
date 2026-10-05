//! The synced cell grid, which the client renders and the predictor reads: built from the live
//! `fux_vt::Screen` on the server, from [`ScreenDiff`](super::ScreenDiff) rows on the client.

use std::cmp::Reverse;
use std::collections::HashMap;
use std::num::{NonZeroI16, NonZeroU16};
use std::sync::Arc;

use fux_vt::{
    Attributes, Cell, CellRef, Cells, Color, MouseProtocolEncoding, MouseProtocolMode, RowId,
};

use super::{Shift, Shifts, MAX_SHIFTS};
use crate::predict::{CellView, ScreenView, Size};

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

/// A hyperlink (OSC 8): its URI, and the id the program gave it, empty for none.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Link {
    pub uri: String,
    pub id: String,
}

impl Link {
    /// Whether this link may be painted as one: a URI of printable ASCII (no space) within
    /// [`fux_vt::URI_LIMIT`], and an id of printable ASCII without `;` or `:` within
    /// [`fux_vt::ID_LIMIT`]. A server could send anything, and a link is written to the user's
    /// terminal inside an escape sequence, so one that is not is painted as plain text.
    pub fn safe(&self) -> bool {
        let printable = |b: &u8| (0x21..=0x7e).contains(b);
        !self.uri.is_empty()
            && self.uri.len() <= fux_vt::URI_LIMIT
            && self.uri.bytes().all(|b| printable(&b))
            && self.id.len() <= fux_vt::ID_LIMIT
            && self
                .id
                .bytes()
                .all(|b| printable(&b) && b != b';' && b != b':')
    }

    /// The bytes this link costs: its URI and its id.
    pub fn len(&self) -> usize {
        self.uri.len().saturating_add(self.id.len())
    }

    pub fn is_empty(&self) -> bool {
        self.uri.is_empty() && self.id.is_empty()
    }
}

/// The most distinct links one row keeps. A row with more keeps the first, and its other cells
/// show no link.
pub const MAX_ROW_LINKS: usize = 64;

/// A row's links: each distinct one once, and by column the one each cell has (0 for none, else
/// one more than its place in `table`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RowLinks {
    pub(super) table: Vec<Link>,
    pub(super) cells: Vec<u16>,
}

impl RowLinks {
    /// The link of the cell at `col`.
    pub fn at(&self, col: usize) -> Option<&Link> {
        let index = usize::from(*self.cells.get(col)?);
        self.table.get(index.checked_sub(1)?)
    }

    /// The bytes the links cost.
    pub(super) fn bytes(&self) -> usize {
        self.table.iter().map(Link::len).sum()
    }

    /// The links of a live row, `cols` wide, or `None` if it has none.
    pub(super) fn of(row: &fux_vt::Row<'_>, cols: u16) -> Option<Arc<Self>> {
        if !row.has_links() {
            return None;
        }
        let mut links = Self::default();
        for col in 0..usize::from(cols) {
            let index = row.link(col).map_or(0, |link| {
                let link = Link {
                    uri: link.uri().to_owned(),
                    id: link.id().unwrap_or_default().to_owned(),
                };
                let at = links.table.iter().position(|l| *l == link).or_else(|| {
                    (links.table.len() < MAX_ROW_LINKS).then(|| {
                        links.table.push(link);
                        links.table.len().saturating_sub(1)
                    })
                });
                at.and_then(|at| u16::try_from(at.saturating_add(1)).ok())
                    .unwrap_or(0)
            });
            links.cells.push(index);
        }
        (!links.table.is_empty()).then(|| Arc::new(links))
    }
}

/// One row of a [`Grid`]: its cells with their text, shared by every screen that holds the row
/// unchanged, whether it soft-wraps into the next, and its cells' links.
#[derive(Clone, Debug)]
struct Row {
    cells: Arc<Cells>,
    wrapped: bool,
    links: Option<Arc<RowLinks>>,
}

impl Row {
    /// A row of `cols` blank cells.
    fn blank(cols: u16) -> Self {
        Self {
            cells: Arc::new(Cells::new(usize::from(cols))),
            wrapped: false,
            links: None,
        }
    }

    /// Whether `self` and `other` share one allocation of cells.
    fn shares(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.cells, &other.cells)
    }

    /// The allocation this row's cells live in, which every row sharing them has too.
    fn id(&self) -> *const Cells {
        Arc::as_ptr(&self.cells)
    }
}

impl PartialEq for Row {
    fn eq(&self, other: &Self) -> bool {
        self.wrapped == other.wrapped
            && self.links == other.links
            && (self.shares(other) || self.cells == other.cells)
    }
}

impl Eq for Row {}

/// The colours a program set (OSC 4, and the default foreground and background with OSC 10 and
/// 11), by which a snapshot draws its cells: each set entry, and each set default, as RGB.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Palette {
    /// By index, the colour the program set it to; `None` where it left it alone or reset it.
    entries: Vec<Option<(u8, u8, u8)>>,
    foreground: Option<(u8, u8, u8)>,
    background: Option<(u8, u8, u8)>,
}

impl Palette {
    /// The colours `screen`'s program set, or `None` if it set none, as most do not.
    pub(super) fn of(screen: &fux_vt::Screen) -> Option<Self> {
        screen.colors_changed().then(|| Self {
            entries: (0..=u8::MAX).map(|i| screen.palette_color(i)).collect(),
            foreground: screen.dynamic_color(10),
            background: screen.dynamic_color(11),
        })
    }

    /// `attributes` in these colours: an indexed colour whose entry was set as the colour set,
    /// and the default foreground and background, if set, as those; every other colour as it is,
    /// for the user's terminal to draw in its own. A default underline colour is the text's, and
    /// stays.
    fn draw(&self, attributes: Attributes) -> Attributes {
        let rgb = |(r, g, b): (u8, u8, u8)| Color::Rgb(r, g, b);
        let colour = |c: Color, default: Option<(u8, u8, u8)>| match c {
            Color::Idx(n) => self
                .entries
                .get(usize::from(n))
                .copied()
                .flatten()
                .map_or(c, rgb),
            Color::Default => default.map_or(c, rgb),
            Color::Rgb(..) | _ => c,
        };
        attributes
            .with_foreground(colour(attributes.foreground(), self.foreground))
            .with_background(colour(attributes.background(), self.background))
            .with_underline_color(colour(attributes.underline_color(), None))
    }

    /// `cells` drawn in these colours. The right half of a wide glyph is drawn with its left.
    fn recolor(&self, cells: &mut Cells) {
        for i in 0..cells.len() {
            let Some(attributes) = cells
                .get(i)
                .filter(|cell| !cell.is_wide_continuation())
                .map(|cell| cell.attributes())
            else {
                continue;
            };
            let drawn = self.draw(attributes);
            if drawn != attributes {
                cells.set_attributes(i, drawn);
            }
        }
    }
}

/// `attributes` as a snapshot of `screen` draws them: in the colours its program set, if any. What
/// a terminal reading the client's paint shows for a cell of `screen`.
pub fn drawn(attributes: Attributes, screen: &fux_vt::Screen) -> Attributes {
    Palette::of(screen).map_or(attributes, |palette| palette.draw(attributes))
}

/// The last snapshot's rows, with each one's fux-vt row id and version then: a row whose cells are
/// unchanged is shared with the next snapshot, wherever it moved, instead of copied.
#[derive(Default)]
pub(super) struct RowCache {
    /// The palette the rows were drawn in. A new palette changes no row's version, so it starts
    /// the cache over.
    palette: Option<Palette>,
    /// By live index, the id and version of the row the snapshot took there.
    ids: Vec<(RowId, u64)>,
    /// The snapshot's rows, which the next one shares whole when no row changed.
    lines: Arc<[Row]>,
    /// The screen as of the snapshot: what changed since, it says.
    mark: Option<fux_vt::Mark>,
}

impl RowCache {
    /// The cached row for the live row `live` at `index`, if it is what it holds: its own row
    /// found by id (at the same index, else by `by_id`, built on first need), at the cached version
    /// or, at another version, with the same cells and no links.
    fn cells(
        &self,
        index: usize,
        live: &fux_vt::Row<'_>,
        by_id: &mut Option<HashMap<RowId, usize>>,
    ) -> Option<(Arc<Cells>, Option<Arc<RowLinks>>)> {
        let at = if self.ids.get(index).is_some_and(|(id, _)| *id == live.id()) {
            index
        } else {
            let by_id = by_id.get_or_insert_with(|| {
                (0..)
                    .zip(&self.ids)
                    .map(|(at, (id, _))| (*id, at))
                    .collect()
            });
            *by_id.get(&live.id())?
        };
        let (_, version) = self.ids.get(at)?;
        let line = self.lines.get(at)?;
        let cells = &line.cells;
        // fux-vt gives a row a new version with each edit that changes it, its links included,
        // and with no other, so a row at the version it was cached at holds the same cells without
        // comparing them. A row with a new version may still hold the same cells (erased, then
        // written back), so it is compared, if neither has links.
        let same = *version == live.version()
            || (line.links.is_none() && !live.has_links() && cells.iter().eq(live.cells()));
        (cells.len() == live.len() && same).then(|| (Arc::clone(cells), line.links.clone()))
    }

    /// Whether the live rows `rows` are exactly the cached ones: the same ids, at the same
    /// versions and places, with the same wrap flags and widths.
    fn holds(&self, rows: &[fux_vt::Row<'_>]) -> bool {
        rows.len() == self.ids.len()
            && rows.iter().zip(&self.ids).zip(self.lines.iter()).all(
                |((live, (id, version)), line)| {
                    live.id() == *id
                        && live.version() == *version
                        && live.wrapped() == line.wrapped
                        && live.len() == line.cells.len()
                },
            )
    }
}

/// A copy of `row`, cells and text, exactly `cols` wide, drawn in `palette`. A live row is exactly
/// that wide; anything longer is cut, anything shorter padded with blank cells.
pub(super) fn exactly(
    row: Option<&fux_vt::Row<'_>>,
    cols: u16,
    palette: Option<&Palette>,
) -> Arc<Cells> {
    let mut cells: Cells = row.map_or_else(Cells::default, |row| row.cells().collect());
    if cells.len() != usize::from(cols) {
        cells.resize(usize::from(cols), Cell::default());
    }
    if let Some(palette) = palette {
        palette.recolor(&mut cells);
    }
    Arc::new(cells)
}

/// A screen of `fux_vt::Cell`s with a cursor, soft-wrap flags and modes.
///
/// Always exactly `rows` rows of `cols` cells. Screens share the rows they hold unchanged. The cursor column may equal `cols`
/// while an autowrap is pending.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grid {
    size: Size,
    /// Shared by every grid that holds them all unchanged, so copying a grid copies no row; a grid
    /// that replaces a row takes its own list first.
    lines: Arc<[Row]>,
    cursor: (u16, u16),
    modes: Modes,
}

impl Grid {
    /// A blank grid (default cells, cursor home, default modes). Every row shares one allocation.
    pub fn blank(size: Size) -> Self {
        let blank = Row::blank(size.cols);
        Self {
            size,
            lines: vec![blank; usize::from(size.rows)].into(),
            cursor: (0, 0),
            modes: Modes::default(),
        }
    }

    /// The live rows, cursor and modes of a fux-vt screen, sharing the rows `cache` holds unchanged;
    /// `cache` is left holding this snapshot's rows.
    pub(super) fn of(screen: &fux_vt::Screen, cache: &mut RowCache) -> Self {
        let (rows, cols) = screen.size();
        if let Some(grid) = Self::of_dirty(screen, cache) {
            return grid;
        }
        let window = screen.window(0, rows, cols);
        let live: Vec<fux_vt::Row<'_>> = (0..rows).filter_map(|row| window.row(row)).collect();
        let palette = Palette::of(screen);
        if palette != cache.palette {
            *cache = RowCache {
                palette,
                ..RowCache::default()
            };
        }
        // If not a row changed, the last snapshot's rows are shared whole.
        if live.len() != usize::from(rows) || !cache.holds(&live) {
            let mut by_id = None;
            let lines: Vec<Row> = (0..usize::from(rows))
                .map(|index| {
                    let Some(row) = live.get(index) else {
                        return Row {
                            cells: exactly(None, cols, cache.palette.as_ref()),
                            wrapped: false,
                            links: None,
                        };
                    };
                    let (cells, links) = cache.cells(index, row, &mut by_id).unwrap_or_else(|| {
                        (
                            exactly(Some(row), cols, cache.palette.as_ref()),
                            RowLinks::of(row, cols),
                        )
                    });
                    Row {
                        cells,
                        wrapped: row.wrapped(),
                        links,
                    }
                })
                .collect();
            cache.ids = live.iter().map(|row| (row.id(), row.version())).collect();
            cache.lines = lines.into();
        }
        cache.mark = Some(screen.mark());
        Self {
            size: Size { rows, cols },
            lines: Arc::clone(&cache.lines),
            cursor: screen.cursor_position(),
            modes: Modes::of(screen),
        }
    }

    /// The rows of `screen` scrolled `offset` rows back into its history (all of it at most), as
    /// the server's emulator shows them, with its cursor and modes: what a client's scrollback
    /// view at `offset` must show, built without the row cache.
    pub(super) fn window_of(screen: &fux_vt::Screen, offset: usize) -> Self {
        let (rows, cols) = screen.size();
        let window = screen.window(offset, rows, cols);
        let palette = Palette::of(screen);
        let lines: Vec<Row> = (0..rows)
            .map(|r| {
                let row = window.row(r);
                Row {
                    cells: exactly(row.as_ref(), cols, palette.as_ref()),
                    wrapped: row.is_some_and(|row| row.wrapped()),
                    links: row.as_ref().and_then(|row| RowLinks::of(row, cols)),
                }
            })
            .collect();
        Self {
            size: Size { rows, cols },
            lines: lines.into(),
            cursor: screen.cursor_position(),
            modes: Modes::of(screen),
        }
    }

    /// The snapshot from the rows that changed since the last one alone, when nothing but rows'
    /// contents did (fux-vt says so): a snapshot's cost then follows what changed, not the screen's
    /// size. `None` when the screen changed otherwise (a scroll, resize, reset, a switch of screens,
    /// the palette), for the full snapshot.
    fn of_dirty(screen: &fux_vt::Screen, cache: &mut RowCache) -> Option<Self> {
        let mark = cache.mark?;
        let (rows, cols) = screen.size();
        if screen.full_refresh_since(mark)
            || Palette::of(screen) != cache.palette
            || cache.lines.len() != usize::from(rows)
            || cache
                .lines
                .first()
                .is_some_and(|line| line.cells.len() != usize::from(cols))
        {
            return None;
        }
        let mut lines: Option<Vec<Row>> = None;
        for (index, row) in screen.dirty_live_rows_since(mark) {
            let at = usize::from(index);
            let line = Row {
                cells: exactly(Some(&row), cols, cache.palette.as_ref()),
                wrapped: row.wrapped(),
                links: RowLinks::of(&row, cols),
            };
            let lines = lines.get_or_insert_with(|| cache.lines.to_vec());
            *lines.get_mut(at)? = line;
            *cache.ids.get_mut(at)? = (row.id(), row.version());
        }
        if let Some(lines) = lines {
            cache.lines = lines.into();
        }
        cache.mark = Some(screen.mark());
        Some(Self {
            size: Size { rows, cols },
            lines: Arc::clone(&cache.lines),
            cursor: screen.cursor_position(),
            modes: Modes::of(screen),
        })
    }

    pub const fn size(&self) -> Size {
        self.size
    }

    /// The cell at `(row, col)`, or `None` out of bounds.
    pub fn cell(&self, row: u16, col: u16) -> Option<CellRef<'_>> {
        self.row(row)?.get(usize::from(col))
    }

    /// One row's cells, or `None` out of bounds.
    pub fn row(&self, row: u16) -> Option<&Cells> {
        self.lines.get(usize::from(row)).map(|line| &*line.cells)
    }

    /// The hyperlink of the cell at `(row, col)`, if it has one.
    pub fn link(&self, row: u16, col: u16) -> Option<&Link> {
        self.row_links(row)?.at(usize::from(col))
    }

    /// One row's links, or `None` if it has none or is out of bounds.
    pub fn row_links(&self, row: u16) -> Option<&RowLinks> {
        self.lines.get(usize::from(row))?.links.as_deref()
    }

    /// Whether `row` soft-wraps into the next one.
    pub fn row_wrapped(&self, row: u16) -> bool {
        self.lines
            .get(usize::from(row))
            .is_some_and(|line| line.wrapped)
    }

    /// Whether `row` is the same in `self` and `other`: the same cells and wrap flag. Rows that
    /// share their cells compare without reading them.
    pub fn row_eq(&self, other: &Self, row: u16) -> bool {
        let row = usize::from(row);
        self.lines.get(row) == other.lines.get(row)
    }

    /// Whether `row` shows the same cells as `other`'s `other_row`, whatever their wrap flags. Rows
    /// that share their cells compare without reading them.
    pub fn same_cells(&self, row: u16, other: &Self, other_row: u16) -> bool {
        match (
            self.lines.get(usize::from(row)),
            other.lines.get(usize::from(other_row)),
        ) {
            (Some(line), Some(other)) => line.shares(other) || line.cells == other.cells,
            _ => false,
        }
    }

    /// The rows of `base` that moved to become rows of `self`, as runs of rows that moved by the same
    /// offset: at most [`MAX_SHIFTS`], the longest, no two sharing a source or a destination row.
    ///
    /// A row moved when `self` holds the very cells (the same allocation) `base` held elsewhere:
    /// snapshots and applied frames share the cells of rows that only moved. Only the first `height`
    /// rows of each are looked at, and of those only the rows whose cells differ from the other
    /// grid's at the same index: a row still in place moved nowhere. Cells either grid holds in two
    /// such rows are never matched.
    pub(crate) fn moves_from(&self, base: &Self, height: u16) -> Vec<Shift> {
        if self.size != base.size {
            return Vec::new();
        }
        let height = usize::from(height.min(self.size.rows));
        let displaced: Vec<bool> = self
            .lines
            .iter()
            .zip(base.lines.iter())
            .take(height)
            .map(|(line, base)| !line.shares(base))
            .collect();
        if !displaced.contains(&true) {
            return Vec::new();
        }
        let from = unique_rows(base, &displaced);
        // Where each displaced row came from, if it holds cells of one displaced base row.
        let mut sources: Vec<Option<u16>> = (0_u16..)
            .zip(self.lines.iter())
            .zip(&displaced)
            .map(|((row, line), &displaced)| {
                displaced
                    .then(|| from.get(&line.id()).copied().flatten())
                    .flatten()
                    .filter(|&source| source != row)
            })
            .collect();
        // Cells two rows hold came from one base row: neither is a move.
        let mut taken: HashMap<u16, usize> = HashMap::new();
        for &source in sources.iter().flatten() {
            let count = taken.entry(source).or_default();
            *count = count.saturating_add(1);
        }
        for source in &mut sources {
            if source.is_some_and(|source| taken.get(&source) > Some(&1)) {
                *source = None;
            }
        }
        let mut runs: Vec<Shift> = Vec::new();
        // The last row that moved, and the row it came from.
        let mut last: Option<(u16, u16)> = None;
        for (row, &source) in (0_u16..).zip(&sources) {
            let Some(source) = source else {
                last = None;
                continue;
            };
            let continues = last.is_some_and(|(prev_row, prev_source)| {
                prev_row.checked_add(1) == Some(row) && prev_source.checked_add(1) == Some(source)
            });
            let extended = continues
                && runs
                    .last_mut()
                    .is_some_and(|run| run.len.checked_add(1).map(|len| run.len = len).is_some());
            if !extended {
                let by = i16::try_from(i32::from(row).saturating_sub(i32::from(source)))
                    .ok()
                    .and_then(NonZeroI16::new);
                if let Some(by) = by {
                    runs.push(Shift {
                        top: source,
                        len: NonZeroU16::MIN,
                        by,
                    });
                }
            }
            last = Some((row, source));
        }
        if runs.len() > MAX_SHIFTS {
            runs.sort_by_key(|run| Reverse(run.len));
            runs.truncate(MAX_SHIFTS);
            runs.sort_by_key(|run| run.top);
        }
        runs
    }

    /// This grid with `shifts` applied, moving rows as shared cells: `None` if a shift leaves the
    /// screen. A row a shift moved away from and none moved into is blank.
    pub(super) fn shifted(&self, shifts: &Shifts) -> Option<Self> {
        if shifts.is_empty() {
            return Some(self.clone());
        }
        if !shifts.fit(self.size.rows) {
            return None;
        }
        let mut lines = self.lines.to_vec();
        let mut filled = vec![false; usize::from(self.size.rows)];
        for (from, to) in shifts.iter().flat_map(|shift| shift.pairs()) {
            let line = self.lines.get(usize::from(from))?.clone();
            *lines.get_mut(usize::from(to))? = line;
            *filled.get_mut(usize::from(to))? = true;
        }
        let mut blank: Option<Row> = None;
        for (from, _) in shifts.iter().flat_map(|shift| shift.pairs()) {
            if filled.get(usize::from(from)) == Some(&false) {
                let line = blank.get_or_insert_with(|| Row::blank(self.size.cols));
                *lines.get_mut(usize::from(from))? = line.clone();
            }
        }
        Some(Self {
            lines: lines.into(),
            ..self.clone()
        })
    }

    /// Whether `row` shares its cells with `other`'s, rather than holding a copy.
    #[cfg(test)]
    pub(super) fn row_shared(&self, other: &Self, row: u16) -> bool {
        self.lines_share(row, other, row)
    }

    /// Whether `row` shares its cells with `other`'s `other_row`.
    #[cfg(test)]
    pub(super) fn lines_share(&self, row: u16, other: &Self, other_row: u16) -> bool {
        match (
            self.lines.get(usize::from(row)),
            other.lines.get(usize::from(other_row)),
        ) {
            (Some(line), Some(other)) => line.shares(other),
            _ => false,
        }
    }

    /// Whether `self` shares its whole row list with `other`, rather than holding its own.
    #[cfg(test)]
    pub(super) fn shares_all_rows(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.lines, &other.lines)
    }

    /// The cells the rows of `grids` hold, each allocation counted once, found the plain way: the
    /// reference the counts above must agree with.
    #[cfg(test)]
    pub(super) fn cells_counted_plainly<'a>(
        seen: impl IntoIterator<Item = &'a Self>,
        grids: impl IntoIterator<Item = &'a Self>,
    ) -> usize {
        let mut ids: std::collections::HashSet<*const Cells> = seen
            .into_iter()
            .flat_map(|grid| grid.lines.iter().map(Row::id))
            .collect();
        grids
            .into_iter()
            .flat_map(|grid| grid.lines.iter())
            .filter(|line| ids.insert(line.id()))
            .map(|line| line.cells.len())
            .sum()
    }

    /// Row `row`'s shared cells, wrap flag and links, to set into another grid of this width.
    pub(super) fn row_parts(&self, row: u16) -> Option<(Arc<Cells>, bool, Option<Arc<RowLinks>>)> {
        let line = self.lines.get(usize::from(row))?;
        Some((Arc::clone(&line.cells), line.wrapped, line.links.clone()))
    }

    /// Replace `row` with `cells`, which must be exactly `cols` long, and their `links`. Out of
    /// bounds or a wrong length changes nothing.
    pub(super) fn set_row(
        &mut self,
        row: u16,
        cells: Arc<Cells>,
        wrapped: bool,
        links: Option<Arc<RowLinks>>,
    ) {
        if cells.len() != usize::from(self.size.cols) {
            return;
        }
        if usize::from(row) < self.lines.len() {
            if let Some(line) = Arc::make_mut(&mut self.lines).get_mut(usize::from(row)) {
                *line = Row {
                    cells,
                    wrapped,
                    links,
                };
            }
        }
    }

    /// The cells the rows of `grids` hold, each shared row counted once: their memory together.
    pub fn distinct_cells<'a>(grids: impl IntoIterator<Item = &'a Self>) -> usize {
        let mut grids = grids.into_iter();
        let Some(first) = grids.next() else {
            return 0;
        };
        // Sorted, rows sharing an allocation sit together: cheaper than hashing every row.
        let mut rows: Vec<(*const Cells, usize)> = first
            .lines
            .iter()
            .map(|line| (line.id(), line.cells.len()))
            .collect();
        rows.sort_unstable();
        rows.dedup_by_key(|(id, _)| *id);
        let own = rows
            .iter()
            .fold(0_usize, |cells, (_, len)| cells.saturating_add(*len));
        own.saturating_add(Self::cells_beyond(first, grids))
    }

    /// The cells the rows of `grids` hold beyond `base`'s: what keeping them besides it costs.
    ///
    /// Grids are mostly `base`'s rows at `base`'s places, so only the rows that differ from
    /// `base`'s at the same index are gathered, each allocation once, and then `base` is read once
    /// for any of them it holds elsewhere (a row that moved). A grid sharing its whole row list
    /// with `base` or with one already read is skipped.
    pub fn cells_beyond<'a>(base: &Self, grids: impl IntoIterator<Item = &'a Self>) -> usize {
        let mut read: Vec<*const [Row]> = vec![Arc::as_ptr(&base.lines)];
        let mut others: HashMap<*const Cells, usize> = HashMap::new();
        for grid in grids {
            let lines = Arc::as_ptr(&grid.lines);
            if read.contains(&lines) {
                continue;
            }
            read.push(lines);
            for (index, line) in grid.lines.iter().enumerate() {
                if !base.lines.get(index).is_some_and(|at| at.shares(line)) {
                    others.insert(line.id(), line.cells.len());
                }
            }
        }
        if !others.is_empty() {
            for line in base.lines.iter() {
                others.remove(&line.id());
            }
        }
        others
            .values()
            .fold(0_usize, |cells, len| cells.saturating_add(*len))
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
        for row in 0..self.size.rows {
            let line: String = self
                .row(row)
                .into_iter()
                .flat_map(Cells::iter)
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

/// Where each row of `grid` that `rows` picks is, by the allocation of its cells: `None` for cells
/// two of them share.
fn unique_rows(grid: &Grid, rows: &[bool]) -> HashMap<*const Cells, Option<u16>> {
    let mut found = HashMap::new();
    for ((row, line), _) in (0_u16..)
        .zip(grid.lines.iter())
        .zip(rows)
        .filter(|(_, &picked)| picked)
    {
        found
            .entry(line.id())
            .and_modify(|seen: &mut Option<u16>| *seen = None)
            .or_insert(Some(row));
    }
    found
}

impl ScreenView for Grid {
    fn size(&self) -> Size {
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
            wide: c.is_wide(),
            continuation: c.is_wide_continuation(),
        })
    }
}
