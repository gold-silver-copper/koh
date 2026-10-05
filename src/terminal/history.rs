//! Scrollback: the server's history rows, named for the wire, and the bounded part of them a client
//! keeps.
//!
//! The server names each row as it enters its history with the next number of a counter that
//! never goes back, so the rows of its history always carry consecutive names, oldest lowest. Each
//! screen says the newest row's name and how many rows the history holds ([`HistoryMark`]), which
//! is all a client needs to ask for any of them by name ([`HistoryRequest`]). A row keeps its name
//! while it is kept, and its cells do not change in history, so a row the client holds is never
//! sent again. A resize re-lays the history out (reflow), so it names every row afresh.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use fux_vt::{Cell, Cells, RowId};
use serde::{Deserialize, Serialize};

use super::grid::{exactly, Palette, RowLinks};
use super::{cells_of, link_bytes, runs_of, Run, WireLink, MAX_DIM, MAX_LINK_BYTES};

/// Most rows one [`HistoryRequest`] asks for, and one reply carries.
pub const MAX_HISTORY_ROWS: u16 = 256;

/// Most cells one reply carries: [`MAX_HISTORY_ROWS`] rows of a wide screen. Past it the server
/// stops adding rows, and the client asks again for the rest.
pub const MAX_HISTORY_CELLS: usize = 256 * 256;

/// Most cells of history a client keeps: as many as the recent screens it keeps
/// ([`WINDOW_CELLS`](crate::proto::WINDOW_CELLS)).
pub const HISTORY_CACHE_CELLS: usize = 1_000_000;

/// The history as a screen shows it: its newest row's name, and how many rows it holds, whose
/// names are the `len` up to and including `newest`. An empty history is `len` 0.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HistoryMark {
    pub newest: u64,
    pub len: u32,
}

impl HistoryMark {
    /// The name of the oldest row, if any.
    pub fn oldest(self) -> Option<u64> {
        let len = u64::from(self.len);
        (len > 0).then(|| self.newest.saturating_sub(len.saturating_sub(1)))
    }

    /// Whether the history holds the row named `name`.
    pub fn holds(self, name: u64) -> bool {
        self.oldest()
            .is_some_and(|oldest| (oldest..=self.newest).contains(&name))
    }
}

/// A client's request: the rows named up to and including `newest`, at most `count` of them,
/// newest first in what they cover (the reply lists them oldest first).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryRequest {
    pub newest: u64,
    pub count: u16,
}

/// One history row on the wire: its name, its cells as runs (its width is theirs: a history row
/// keeps the width it had), and its links.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryRow {
    pub name: u64,
    pub wrapped: bool,
    pub runs: Vec<Run>,
    pub links: Vec<WireLink>,
}

impl HistoryRow {
    /// The row's width: its runs' cells, if within [`MAX_DIM`].
    fn width(&self) -> Option<u16> {
        let cells = self
            .runs
            .iter()
            .map(|run| usize::from(run.count.get()))
            .try_fold(0_usize, usize::checked_add)?;
        u16::try_from(cells)
            .ok()
            .filter(|&w| (1..=MAX_DIM).contains(&w))
    }
}

/// The server's answer to a [`HistoryRequest`]: the rows it still holds of those asked for,
/// oldest first, consecutive, the last the one asked for. Empty if it holds none of them.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryReply {
    pub rows: Vec<HistoryRow>,
}

/// The server's names for its history rows.
#[derive(Debug, Default)]
pub(super) struct HistoryNames {
    /// The last name given; the first is 1.
    last: u64,
    by_row: HashMap<RowId, u64>,
}

impl HistoryNames {
    /// Forget every name: the history was laid out afresh. Names already given are not given
    /// again.
    pub(super) fn renew(&mut self) {
        self.by_row.clear();
    }

    /// Name the rows that entered `screen`'s history since the last call, in order, and say where
    /// the history stands.
    ///
    /// The rows not named yet are the newest: a row enters history at its newest end, and only a
    /// resize, which renews the names, brings one back. So the walk from the newest row stops at
    /// the first named one, and costs the rows that entered.
    pub(super) fn mark(&mut self, screen: &fux_vt::Screen) -> HistoryMark {
        let len = screen.history_len();
        let rows = usize::from(screen.size().0);
        // History row `h` (0 the oldest) is `len - 1 - h + rows` rows from the bottom.
        let unnamed = (0..len)
            .take_while(|&back| {
                rows.checked_add(back)
                    .and_then(|offset| screen.row_from_bottom(offset))
                    .is_some_and(|row| !self.by_row.contains_key(&row.id()))
            })
            .count();
        for back in (0..unnamed).rev() {
            if let Some(row) = rows
                .checked_add(back)
                .and_then(|offset| screen.row_from_bottom(offset))
            {
                self.last = self.last.saturating_add(1);
                self.by_row.insert(row.id(), self.last);
            }
        }
        // Rows that left history keep their names in the map until it holds twice what is kept.
        let kept = len.saturating_add(rows);
        if self.by_row.len() > kept.saturating_mul(2).saturating_add(64) {
            let present: std::collections::HashSet<RowId> = (0..kept)
                .filter_map(|offset| screen.row_from_bottom(offset).map(|row| row.id()))
                .collect();
            self.by_row.retain(|id, _| present.contains(id));
        }
        let newest = screen
            .row_from_bottom(rows)
            .filter(|_| len > 0)
            .and_then(|row| self.by_row.get(&row.id()).copied());
        match newest {
            Some(newest) => HistoryMark {
                newest,
                len: u32::try_from(len).unwrap_or(u32::MAX),
            },
            None => HistoryMark::default(),
        }
    }

    /// The rows `request` asks for that `screen`'s history holds, drawn in `palette`, oldest first.
    pub(super) fn reply(
        &mut self,
        screen: &fux_vt::Screen,
        palette: Option<&Palette>,
        request: HistoryRequest,
    ) -> HistoryReply {
        let mark = self.mark(screen);
        let count = request.count.min(MAX_HISTORY_ROWS);
        if !mark.holds(request.newest) || count == 0 {
            return HistoryReply::default();
        }
        let rows = usize::from(screen.size().0);
        // Names are consecutive, so the row asked for is this many rows above the newest.
        let Some(above) = usize::try_from(mark.newest.saturating_sub(request.newest)).ok() else {
            return HistoryReply::default();
        };
        let mut out = Vec::new();
        let mut cells = 0_usize;
        let mut links = 0_usize;
        for back in 0..usize::from(count) {
            let Some(row) = rows
                .checked_add(above)
                .and_then(|offset| offset.checked_add(back))
                .filter(|&offset| offset < rows.saturating_add(screen.history_len()))
                .and_then(|offset| screen.row_from_bottom(offset))
            else {
                break;
            };
            let name = request
                .newest
                .saturating_sub(u64::try_from(back).unwrap_or(u64::MAX));
            if self.by_row.get(&row.id()) != Some(&name) {
                break;
            }
            let Some(width) = u16::try_from(row.len()).ok().filter(|&w| w > 0) else {
                break;
            };
            cells = cells.saturating_add(usize::from(width));
            if cells > MAX_HISTORY_CELLS && !out.is_empty() {
                break;
            }
            let row_cells = exactly(Some(&row), width, palette);
            let row_links = RowLinks::of(&row, width)
                .filter(|l| links.saturating_add(l.bytes()) <= MAX_LINK_BYTES);
            links = links.saturating_add(row_links.as_ref().map_or(0, |l| l.bytes()));
            let (runs, wire_links) = runs_of(&row_cells, row_links.as_deref());
            out.push(HistoryRow {
                name,
                wrapped: row.wrapped(),
                runs,
                links: wire_links,
            });
        }
        out.reverse();
        HistoryReply { rows: out }
    }
}

/// A history row as the client keeps it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeptRow {
    pub cells: Arc<Cells>,
    pub wrapped: bool,
    pub links: Option<Arc<RowLinks>>,
}

impl KeptRow {
    /// The row cut or padded to `cols` cells; a wide glyph the cut would halve is blanked.
    pub fn fitted(&self, cols: u16) -> Arc<Cells> {
        let cols = usize::from(cols);
        if self.cells.len() == cols {
            return Arc::clone(&self.cells);
        }
        let mut cells = Cells::clone(&self.cells);
        if cols > 0 && cells.get(cols).is_some_and(|c| c.is_wide_continuation()) {
            cells.set_cell(cols.saturating_sub(1), Cell::default());
        }
        cells.resize(cols, Cell::default());
        Arc::new(cells)
    }

    fn links_fitted(&self, cols: u16) -> Option<Arc<RowLinks>> {
        let links = self.links.as_ref()?;
        if links.cells.len() == usize::from(cols) {
            return Some(Arc::clone(links));
        }
        let mut cells = links.cells.clone();
        cells.resize(usize::from(cols), 0);
        Some(Arc::new(RowLinks {
            table: links.table.clone(),
            cells,
        }))
    }
}

/// The history rows a client holds, by name, at most [`HISTORY_CACHE_CELLS`] cells of them.
#[derive(Debug, Default)]
pub struct HistoryCache {
    rows: BTreeMap<u64, KeptRow>,
    cells: usize,
}

impl HistoryCache {
    /// The row named `name`, if held.
    pub fn get(&self, name: u64) -> Option<&KeptRow> {
        self.rows.get(&name)
    }

    /// Whether the row named `name` is held.
    pub fn holds(&self, name: u64) -> bool {
        self.rows.contains_key(&name)
    }

    /// How many rows are held.
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether no row is held.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// The cells held.
    pub const fn cells(&self) -> usize {
        self.cells
    }

    /// Drop the rows the history no longer holds by `mark`. An empty history (the alternate
    /// screen has none) drops nothing: the rows come back with the primary screen.
    pub fn retain(&mut self, mark: HistoryMark) {
        let Some(oldest) = mark.oldest() else {
            return;
        };
        let gone: Vec<u64> = self
            .rows
            .range(..oldest)
            .chain(self.rows.range(mark.newest.saturating_add(1)..))
            .map(|(name, _)| *name)
            .collect();
        for name in gone {
            self.remove(name);
        }
    }

    fn remove(&mut self, name: u64) {
        if let Some(row) = self.rows.remove(&name) {
            self.cells = self.cells.saturating_sub(row.cells.len());
        }
    }

    /// Keep `reply`'s rows that `mark` says the history holds, then drop the rows farthest from
    /// `near` until the cells held are within the bound. Returns how many rows were kept, or
    /// `None` if the reply is malformed (then nothing of it is kept).
    ///
    /// All server-controlled: every row is decoded and checked before any is kept, the reply's
    /// rows, cells and links are bounded, and what is kept is bounded by cells.
    pub fn insert(&mut self, reply: &HistoryReply, mark: HistoryMark, near: u64) -> Option<usize> {
        if reply.rows.len() > usize::from(MAX_HISTORY_ROWS) {
            return None;
        }
        let mut cells = 0_usize;
        let mut links = 0_usize;
        let mut staged = Vec::with_capacity(reply.rows.len());
        for row in &reply.rows {
            let width = row.width()?;
            cells = cells.checked_add(usize::from(width))?;
            links = links.checked_add(link_bytes(&row.links))?;
            if cells > MAX_HISTORY_CELLS.saturating_add(usize::from(MAX_DIM))
                || links > MAX_LINK_BYTES
            {
                return None;
            }
            let (decoded, row_links) = cells_of(&row.runs, &row.links, width)?;
            staged.push((
                row.name,
                KeptRow {
                    cells: Arc::new(decoded),
                    wrapped: row.wrapped,
                    links: row_links,
                },
            ));
        }
        let mut kept = 0_usize;
        for (name, row) in staged {
            if !mark.holds(name) {
                continue;
            }
            self.remove(name);
            self.cells = self.cells.saturating_add(row.cells.len());
            self.rows.insert(name, row);
            kept = kept.saturating_add(1);
        }
        while self.cells > HISTORY_CACHE_CELLS {
            let first = self.rows.first_key_value().map(|(name, _)| *name);
            let last = self.rows.last_key_value().map(|(name, _)| *name);
            let farthest = match (first, last) {
                (Some(first), Some(last)) => {
                    if near.abs_diff(first) >= near.abs_diff(last) {
                        first
                    } else {
                        last
                    }
                }
                _ => break,
            };
            self.remove(farthest);
        }
        Some(kept)
    }

    /// The row named `name` as a screen row of `cols` cells, with its wrap flag and links.
    pub fn screen_row(
        &self,
        name: u64,
        cols: u16,
    ) -> Option<(Arc<Cells>, bool, Option<Arc<RowLinks>>)> {
        let row = self.rows.get(&name)?;
        Some((row.fitted(cols), row.wrapped, row.links_fitted(cols)))
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU16;

    use super::*;
    use crate::terminal::{
        CellKind, CellText, ServerTerminal, Size, WireCell, WireColor, WireStyle,
    };

    fn lines(emu: &mut ServerTerminal, from: usize, to: usize) {
        for n in from..to {
            emu.process(format!("line {n}\r\n").as_bytes());
        }
    }

    fn text(row: &HistoryRow) -> String {
        let width = row.width().unwrap();
        let (cells, _) = cells_of(&row.runs, &row.links, width).unwrap();
        cells
            .iter()
            .map(|c| c.contents().to_owned())
            .collect::<String>()
            .trim_end()
            .to_owned()
    }

    #[test]
    fn rows_entering_history_take_consecutive_names() {
        let mut emu = ServerTerminal::new(4, 20, 100).unwrap();
        assert_eq!(emu.snapshot().history(), HistoryMark::default());
        lines(&mut emu, 0, 10);
        // Ten lines and the cursor's row on four rows: seven scrolled off.
        let mark = emu.snapshot().history();
        assert_eq!(mark.len, 7);
        lines(&mut emu, 10, 13);
        let later = emu.snapshot().history();
        assert_eq!((later.newest - mark.newest, later.len), (3, 10));
        let reply = emu.history(HistoryRequest {
            newest: later.newest,
            count: 10,
        });
        let texts: Vec<String> = reply.rows.iter().map(text).collect();
        assert_eq!(
            texts,
            (0..10).map(|n| format!("line {n}")).collect::<Vec<_>>()
        );
        let names: Vec<u64> = reply.rows.iter().map(|r| r.name).collect();
        assert_eq!(names, (later.newest - 9..=later.newest).collect::<Vec<_>>());
    }

    #[test]
    fn a_reply_holds_only_what_the_history_holds_and_at_most_the_bound() {
        let mut emu = ServerTerminal::new(4, 20, 1000).unwrap();
        lines(&mut emu, 0, 600);
        let mark = emu.snapshot().history();
        let ask = |emu: &mut ServerTerminal, newest, count| {
            emu.history(HistoryRequest { newest, count }).rows.len()
        };
        assert_eq!(
            ask(&mut emu, mark.newest, u16::MAX),
            usize::from(MAX_HISTORY_ROWS)
        );
        assert_eq!(ask(&mut emu, mark.newest, 0), 0);
        assert_eq!(
            ask(&mut emu, mark.newest.saturating_add(1), 5),
            0,
            "not yet named"
        );
        assert_eq!(ask(&mut emu, 0, 5), 0, "never named");
        let oldest = mark.oldest().unwrap();
        assert_eq!(
            ask(&mut emu, oldest.saturating_add(2), 50),
            3,
            "the oldest three"
        );
        assert_eq!(ask(&mut emu, u64::MAX, u16::MAX), 0);
    }

    #[test]
    fn a_reply_stops_at_the_cell_bound() {
        let mut emu = ServerTerminal::new(4, 1000, 1000).unwrap();
        for _ in 0..300 {
            emu.process(&[b'x'; 1000]);
            emu.process(b"\r\n");
        }
        let mark = emu.snapshot().history();
        let reply = emu.history(HistoryRequest {
            newest: mark.newest,
            count: MAX_HISTORY_ROWS,
        });
        let cells: usize = reply
            .rows
            .iter()
            .map(|r| usize::from(r.width().unwrap()))
            .sum();
        assert!(cells <= MAX_HISTORY_CELLS, "{cells}");
        assert_eq!(reply.rows.len(), MAX_HISTORY_CELLS.div_euclid(1000));
    }

    #[test]
    fn a_resize_names_every_row_afresh() {
        let mut emu = ServerTerminal::new(4, 20, 100).unwrap();
        lines(&mut emu, 0, 20);
        let before = emu.snapshot().history();
        emu.resize(Size::new(6, 10));
        let after = emu.snapshot().history();
        assert!(
            after.oldest().unwrap() > before.newest,
            "{before:?} {after:?}"
        );
        let reply = emu.history(HistoryRequest {
            newest: before.newest,
            count: 5,
        });
        assert!(reply.rows.is_empty(), "old names are gone");
    }

    fn row(name: u64, width: u16) -> HistoryRow {
        HistoryRow {
            name,
            wrapped: false,
            runs: vec![Run {
                count: NonZeroU16::new(width).unwrap(),
                cell: WireCell {
                    text: CellText::new("y").unwrap(),
                    kind: CellKind::Narrow,
                    fg: WireColor::Default,
                    bg: WireColor::Default,
                    underline_color: WireColor::Default,
                    style: WireStyle::default(),
                    link: 0,
                },
            }],
            links: Vec::new(),
        }
    }

    const MARK: HistoryMark = HistoryMark {
        newest: 10_000,
        len: 10_000,
    };

    #[test]
    fn the_cache_keeps_only_rows_the_history_holds() {
        let mut cache = HistoryCache::default();
        let reply = HistoryReply {
            rows: vec![row(0, 5), row(1, 5), row(10_000, 5), row(10_001, 5)],
        };
        assert_eq!(cache.insert(&reply, MARK, 1), Some(2));
        assert!(cache.holds(1) && cache.holds(10_000) && !cache.holds(10_001));
        cache.retain(HistoryMark {
            newest: 10_005,
            len: 10,
        });
        assert!(!cache.holds(1) && cache.holds(10_000));
        // An empty history (the alternate screen) drops nothing.
        cache.retain(HistoryMark::default());
        assert!(cache.holds(10_000));
    }

    #[test]
    fn a_malformed_reply_keeps_nothing() {
        let too_wide = HistoryRow {
            runs: vec![row(2, 1000).runs[0].clone(), row(2, 1).runs[0].clone()],
            ..row(2, 1)
        };
        let bad_link = HistoryRow {
            runs: vec![Run {
                cell: WireCell {
                    link: 1,
                    ..row(3, 4).runs[0].cell.clone()
                },
                ..row(3, 4).runs[0].clone()
            }],
            ..row(3, 4)
        };
        let too_many = HistoryReply {
            rows: (1..=u64::from(MAX_HISTORY_ROWS) + 1)
                .map(|n| row(n, 1))
                .collect(),
        };
        let too_many_cells = HistoryReply {
            rows: (1..=100).map(|n| row(n, 1000)).collect(),
        };
        for reply in [
            HistoryReply {
                rows: vec![row(1, 3), too_wide],
            },
            HistoryReply {
                rows: vec![row(1, 3), bad_link],
            },
            too_many,
            too_many_cells,
        ] {
            let mut cache = HistoryCache::default();
            assert_eq!(cache.insert(&reply, MARK, 1), None);
            assert!(cache.is_empty());
        }
    }

    #[test]
    fn the_cache_is_bounded_by_cells_dropping_the_rows_farthest_from_the_view() {
        let mut cache = HistoryCache::default();
        let per_reply = MAX_HISTORY_CELLS.div_euclid(1000);
        let mut name = 1_u64;
        // Far more than the bound, as a hostile server would send.
        for _ in 0..HISTORY_CACHE_CELLS.div_euclid(MAX_HISTORY_CELLS) * 3 {
            let rows = (0..per_reply)
                .map(|_| {
                    name += 1;
                    row(name, 1000)
                })
                .collect();
            cache.insert(&HistoryReply { rows }, MARK, 2).unwrap();
            assert!(cache.cells() <= HISTORY_CACHE_CELLS);
        }
        assert!(cache.holds(2), "the row the view is on stays");
        assert!(!cache.holds(name), "the farthest went");
    }

    #[test]
    fn a_row_is_fitted_to_the_screen_without_halving_a_wide_glyph() {
        let mut cells = Cells::new(4);
        cells.set_text(2, "日", true, fux_vt::Attributes::default());
        cells.set_cell(3, Cell::wide_continuation());
        let kept = KeptRow {
            cells: Arc::new(cells),
            wrapped: false,
            links: None,
        };
        let cut = kept.fitted(3);
        assert_eq!(cut.len(), 3);
        assert!(
            cut.iter().all(|c| !c.is_wide()),
            "the halved glyph is blank"
        );
        assert_eq!(kept.fitted(6).len(), 6);
    }
}
