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

use fux_vt::{CellRef, Cells, RowId};
use serde::{Deserialize, Serialize};

use super::grid::{exactly, Palette, RowLinks, Uses};
use super::{
    cells_of, link_bytes, runs_of, RowFlags, Run, WireLink, DIM, MAX_DIM, MAX_LINK_BYTES,
    MAX_ROW_LINKS,
};

/// Most rows one [`HistoryRequest`] asks for, and one reply carries.
pub const MAX_HISTORY_ROWS: u16 = 256;

/// [`MAX_HISTORY_ROWS`], as a count of a reply's rows.
const HISTORY_ROWS: usize = MAX_HISTORY_ROWS as usize;

/// Most cells one reply carries: [`MAX_HISTORY_ROWS`] rows of a wide screen. Past it the server
/// stops adding rows, and the client asks again for the rest.
pub const MAX_HISTORY_CELLS: usize = 256 * 256;

/// Most bytes a reply the server may send inflates to.
///
/// Its cells, past [`MAX_HISTORY_CELLS`] by a row at most, each a run of its own of the longest
/// cluster (its count, kind, colours, style and link are under 32 bytes); each row's name, flag,
/// lengths and links' lengths; and the links.
pub const MAX_HISTORY_REPLY: usize = (MAX_HISTORY_CELLS + DIM) * (fux_vt::CLUSTER_CAPACITY + 32)
    + HISTORY_ROWS * (32 + MAX_ROW_LINKS * 8)
    + MAX_LINK_BYTES;

/// Most bytes of history a client keeps, by [`KeptRow::bytes`]: what a server chooses to send is
/// bounded by memory, not by a count its rows' links or overhead could multiply.
pub const HISTORY_CACHE_BYTES: usize = 64 << 20;

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

/// A client's request `id`: the rows named up to and including `newest`, at most `count` of them,
/// newest first in what they cover (the reply lists them oldest first).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryRequest {
    pub id: u64,
    pub newest: u64,
    pub count: u16,
}

impl HistoryRequest {
    /// Whether it asks for the row named `name`.
    pub fn covers(self, name: u64) -> bool {
        name <= self.newest && self.newest.saturating_sub(name) < u64::from(self.count)
    }

    /// The answer that holds no rows.
    pub fn none(self) -> HistoryReply {
        HistoryReply {
            id: self.id,
            rows: Vec::new(),
        }
    }
}

/// One history row on the wire: its name, its flags, its cells as runs (its width is theirs: a
/// history row keeps the width it had), and its links.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryRow {
    pub name: u64,
    pub flags: RowFlags,
    #[serde(deserialize_with = "crate::bounded::at_most::<{ super::DIM }, _, _>")]
    pub runs: Vec<Run>,
    #[serde(deserialize_with = "crate::bounded::at_most::<{ super::MAX_ROW_LINKS }, _, _>")]
    pub links: Vec<WireLink>,
}

impl HistoryRow {
    /// The row's width: its runs' cells, if within [`MAX_DIM`].
    fn width(&self) -> Option<u16> {
        let cells = self
            .runs
            .iter()
            .map(Run::cells)
            .try_fold(0_usize, usize::checked_add)?;
        u16::try_from(cells)
            .ok()
            .filter(|&w| (1..=MAX_DIM).contains(&w))
    }
}

/// The server's answer to the [`HistoryRequest`] `id`: the rows it still holds of those asked for,
/// oldest first, consecutive, the last the one asked for. Empty if it holds none of them.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryReply {
    pub id: u64,
    #[serde(deserialize_with = "crate::bounded::at_most::<HISTORY_ROWS, _, _>")]
    pub rows: Vec<HistoryRow>,
}

/// The server's names for its history rows.
#[derive(Debug, Default)]
pub(super) struct HistoryNames {
    /// The last name given; the first is 1.
    last: u64,
    by_row: HashMap<RowId, u64>,
    /// The colours the rows named use, whose copies a client holds under those names.
    uses: Uses,
}

impl HistoryNames {
    /// Forget every name: the history was laid out afresh. Names already given are not given
    /// again.
    pub(super) fn renew(&mut self) {
        self.by_row.clear();
        self.uses = Uses::default();
    }

    /// Whether palette `new` draws a row named otherwise than `old`, which the rows were named in.
    pub(super) fn redrawn(&self, old: Option<&Palette>, new: Option<&Palette>) -> bool {
        old != new && self.uses.drawn_otherwise(old, new)
    }

    /// Name the rows that entered `screen`'s history since the last call, in order, and say where
    /// the history stands.
    ///
    /// The rows not named yet are the newest: a row enters history at its newest end, and only a
    /// resize, which renews the names, brings one back. So the walk from the newest row stops at
    /// the first named one, and costs the rows that entered.
    pub(super) fn mark(&mut self, screen: &fux_vt::Screen) -> HistoryMark {
        let len = screen.history_len();
        let rows = usize::from(screen.size().rows());
        // History is the prefix of retained rows. Walk its newest unnamed suffix, then
        // give names in chronological order without rebuilding offsets into the live screen.
        let unnamed = screen
            .rows()
            .take(len)
            .rev()
            .take_while(|row| !self.by_row.contains_key(&row.id()))
            .count();
        for row in screen.rows().take(len).skip(len.saturating_sub(unnamed)) {
            self.uses.add(row.cells().map(|cell| cell.attributes()));
            self.last = self.last.saturating_add(1);
            self.by_row.insert(row.id(), self.last);
        }
        // Rows that left history keep their names in the map until it holds twice what is kept.
        // Not on the alternate screen, which has no history: the primary's comes back with it.
        let kept = len.saturating_add(rows);
        if len > 0 && self.by_row.len() > kept.saturating_mul(2).saturating_add(64) {
            let present: std::collections::HashSet<RowId> =
                screen.rows().map(|row| row.id()).collect();
            self.by_row.retain(|id, _| present.contains(id));
        }
        let newest = screen
            .rows()
            .take(len)
            .next_back()
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
        // Names are consecutive, so the row asked for is this many rows above the newest.
        let above = usize::try_from(mark.newest.saturating_sub(request.newest)).ok();
        let Some(above) = above.filter(|_| mark.holds(request.newest) && count > 0) else {
            return request.none();
        };
        let mut out = Vec::new();
        let mut cells = 0_usize;
        let mut links = 0_usize;
        for (back, row) in screen
            .rows()
            .take(screen.history_len())
            .rev()
            .skip(above)
            .take(usize::from(count))
            .enumerate()
        {
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
                flags: RowFlags::of(Some(&row)),
                runs,
                links: wire_links,
            });
        }
        out.reverse();
        HistoryReply {
            id: request.id,
            rows: out,
        }
    }
}

/// A history row as the client keeps it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeptRow {
    pub cells: Arc<Cells>,
    pub flags: RowFlags,
    pub links: Option<Arc<RowLinks>>,
}

impl KeptRow {
    /// The memory the row takes, as fux-vt keeps its cells: eight bytes and the attributes each,
    /// the text of each cluster too long to keep inline (5 to 17 bytes apart, longer ones in
    /// [`Cells::text_len`]); its links' text, table and per-cell indices; and a row's fixed cost,
    /// its allocations' headers and its entry in the cache. Not their spare capacity, which
    /// fux-vt's `Cells::heap_bytes` counts from its next release.
    pub fn bytes(&self) -> usize {
        const ROW_BYTES: usize = 128;
        // fux-vt stores a cell as 8 bytes (a u32 among them) and its attributes, aligned to 4.
        let cell = 8_usize
            .saturating_add(std::mem::size_of::<fux_vt::Attributes>())
            .next_multiple_of(4);
        let apart: usize = self
            .cells
            .iter()
            .map(|cell| cell.contents().len())
            .filter(|len| (5..=17).contains(len))
            .sum();
        let links = self.links.as_ref().map_or(0, |links| {
            links
                .table
                .iter()
                .map(|link| {
                    link.len()
                        .saturating_add(std::mem::size_of::<super::Link>())
                })
                .fold(
                    links
                        .cells
                        .len()
                        .saturating_mul(2)
                        .saturating_add(ROW_BYTES),
                    usize::saturating_add,
                )
        });
        self.cells
            .len()
            .saturating_mul(cell)
            .saturating_add(apart)
            .saturating_add(self.cells.text_len())
            .saturating_add(links)
            .saturating_add(ROW_BYTES)
    }

    /// The row's text, cell by cell, a blank cell a space.
    pub fn text(&self) -> String {
        self.cells
            .iter()
            .filter(|cell| !cell.is_wide_continuation())
            .map(|cell| {
                let text = cell.contents();
                if text.is_empty() { " " } else { text }.to_owned()
            })
            .collect()
    }

    /// The row cut or padded to `cols` cells; a wide glyph the cut would halve is blanked.
    pub fn fitted(&self, cols: u16) -> Arc<Cells> {
        let cols = usize::from(cols);
        if self.cells.len() == cols {
            return Arc::clone(&self.cells);
        }
        let mut cells = Cells::clone(&self.cells);
        if cols > 0 && cells.get(cols).is_some_and(|c| c.is_wide_continuation()) {
            cells.set(cols.saturating_sub(1), CellRef::default());
        }
        cells.resize(cols, CellRef::default());
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

/// The history rows a client holds, by name, at most [`HISTORY_CACHE_BYTES`] of them.
#[derive(Debug, Default)]
pub struct HistoryCache {
    rows: BTreeMap<u64, KeptRow>,
    bytes: usize,
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

    /// The bytes held, by [`KeptRow::bytes`].
    pub const fn bytes(&self) -> usize {
        self.bytes
    }

    /// Drop the rows the history no longer holds by `mark`. An empty history (the alternate
    /// screen has none) drops nothing: the rows come back, under their names, with the primary
    /// screen.
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
            self.bytes = self.bytes.saturating_sub(row.bytes());
        }
    }

    /// Keep `reply`'s rows that the request `asked` was for and `mark` says the history holds, then
    /// drop the rows farthest from the `view` until the bytes held are within the bound, but never
    /// one the view shows or one just kept, which the caller is about to read. Returns how
    /// many rows were kept, or `None` if the reply is malformed (then nothing of it is kept).
    ///
    /// All server-controlled: every row is decoded and checked before any is kept, the reply's
    /// rows, cells and links are bounded, and what is kept is bounded by bytes, past the bound by
    /// the protected rows alone.
    pub fn insert(
        &mut self,
        reply: &HistoryReply,
        asked: HistoryRequest,
        mark: HistoryMark,
        view: std::ops::RangeInclusive<u64>,
    ) -> Option<usize> {
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
                    flags: row.flags,
                    links: row_links,
                },
            ));
        }
        let mut kept = Vec::with_capacity(staged.len());
        for (name, row) in staged {
            if !(asked.covers(name) && mark.holds(name)) {
                continue;
            }
            self.remove(name);
            self.bytes = self.bytes.saturating_add(row.bytes());
            self.rows.insert(name, row);
            kept.push(name);
        }
        kept.sort_unstable();
        let protected = |name: &u64| view.contains(name) || kept.binary_search(name).is_ok();
        let near = *view.start();
        while self.bytes > HISTORY_CACHE_BYTES {
            let first = self.rows.keys().find(|name| !protected(name)).copied();
            let last = self
                .rows
                .keys()
                .rev()
                .find(|name| !protected(name))
                .copied();
            let farthest = match (first, last) {
                (Some(first), Some(last)) if near.abs_diff(first) >= near.abs_diff(last) => first,
                (_, Some(last)) => last,
                (_, None) => break,
            };
            self.remove(farthest);
        }
        Some(kept.len())
    }

    /// The row named `name` as a screen row of `cols` cells, with its flags and links.
    pub fn screen_row(
        &self,
        name: u64,
        cols: u16,
    ) -> Option<(Arc<Cells>, RowFlags, Option<Arc<RowLinks>>)> {
        let row = self.rows.get(&name)?;
        Some((row.fitted(cols), row.flags, row.links_fitted(cols)))
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU16;

    use super::*;
    use crate::terminal::{
        CellKind, CellText, ServerTerminal, Size, WireCell, WireColor, WireStyle, MAX_ROW_LINKS,
    };

    /// Request 0: at most `count` rows up to `newest`.
    const fn ask(newest: u64, count: u16) -> HistoryRequest {
        HistoryRequest {
            id: 0,
            newest,
            count,
        }
    }

    /// The reply to request 0 holding `rows`.
    fn reply(rows: Vec<HistoryRow>) -> HistoryReply {
        HistoryReply { id: 0, rows }
    }

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
        let mut emu = ServerTerminal::new(4, 20, 1 << 20).unwrap();
        assert_eq!(emu.snapshot().history(), HistoryMark::default());
        lines(&mut emu, 0, 10);
        // Ten lines and the cursor's row on four rows: seven scrolled off.
        let mark = emu.snapshot().history();
        assert_eq!(mark.len, 7);
        lines(&mut emu, 10, 13);
        let later = emu.snapshot().history();
        assert_eq!((later.newest - mark.newest, later.len), (3, 10));
        let reply = emu.history(ask(later.newest, 10));
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
        let mut emu = ServerTerminal::new(4, 20, 1 << 20).unwrap();
        lines(&mut emu, 0, 600);
        let mark = emu.snapshot().history();
        let rows =
            |emu: &mut ServerTerminal, newest, count| emu.history(ask(newest, count)).rows.len();
        assert_eq!(
            rows(&mut emu, mark.newest, u16::MAX),
            usize::from(MAX_HISTORY_ROWS)
        );
        assert_eq!(rows(&mut emu, mark.newest, 0), 0);
        assert_eq!(
            rows(&mut emu, mark.newest.saturating_add(1), 5),
            0,
            "not yet named"
        );
        assert_eq!(rows(&mut emu, 0, 5), 0, "never named");
        let oldest = mark.oldest().unwrap();
        assert_eq!(
            rows(&mut emu, oldest.saturating_add(2), 50),
            3,
            "the oldest three"
        );
        assert_eq!(rows(&mut emu, u64::MAX, u16::MAX), 0);
    }

    #[test]
    fn a_reply_stops_at_the_cell_bound() {
        let mut emu = ServerTerminal::new(4, 1000, 16 << 20).unwrap();
        for _ in 0..300 {
            emu.process(&[b'x'; 1000]);
            emu.process(b"\r\n");
        }
        let mark = emu.snapshot().history();
        let reply = emu.history(ask(mark.newest, MAX_HISTORY_ROWS));
        let cells: usize = reply
            .rows
            .iter()
            .map(|r| usize::from(r.width().unwrap()))
            .sum();
        assert!(cells <= MAX_HISTORY_CELLS, "{cells}");
        assert_eq!(reply.rows.len(), MAX_HISTORY_CELLS.div_euclid(1000));
    }

    #[test]
    fn the_largest_reply_the_server_may_send_inflates_within_its_bound() {
        // Every cell a run of its own, of the longest cluster in true colours, naming the last of
        // the most links a row has; the cells past the bound by a row, the links' bytes at theirs.
        let rgb = WireColor::Rgb(255, 255, 255);
        let run = Run {
            count: NonZeroU16::MIN,
            cell: WireCell {
                text: CellText::run(&"\u{301}".repeat(fux_vt::CLUSTER_CAPACITY.div_euclid(2)))
                    .unwrap(),
                kind: CellKind::Narrow,
                fg: rgb,
                bg: rgb,
                underline_color: rgb,
                style: WireStyle::default(),
                link: u16::try_from(MAX_ROW_LINKS).unwrap(),
            },
        };
        let link = WireLink {
            uri: "u".repeat(MAX_LINK_BYTES.div_euclid(HISTORY_ROWS * MAX_ROW_LINKS)),
            id: String::new(),
        };
        let row = HistoryRow {
            name: u64::MAX,
            flags: RowFlags {
                wrapped: true,
                prompt: true,
            },
            runs: vec![run; (MAX_HISTORY_CELLS + DIM).div_euclid(HISTORY_ROWS)],
            links: vec![link; MAX_ROW_LINKS],
        };
        let largest = reply(vec![row; HISTORY_ROWS]);
        assert!(postcard::to_allocvec(&largest).unwrap().len() <= MAX_HISTORY_REPLY);
    }

    /// `CSI 3 J` drops the history: its rows are not there to fetch, and the rows that enter it
    /// next take new names.
    #[test]
    fn a_cleared_history_holds_nothing_and_names_what_enters_it_afresh() {
        let mut emu = ServerTerminal::new(4, 20, 1 << 20).unwrap();
        lines(&mut emu, 0, 10);
        let before = emu.snapshot().history();
        emu.process(b"\x1b[3J");
        assert_eq!(emu.snapshot().history(), HistoryMark::default());
        assert!(emu.history(ask(before.newest, 5)).rows.is_empty(), "gone");
        lines(&mut emu, 10, 12);
        let after = emu.snapshot().history();
        assert_eq!(after.len, 2);
        assert!(after.oldest() > Some(before.newest), "{before:?} {after:?}");
    }

    #[test]
    fn a_resize_names_every_row_afresh() {
        let mut emu = ServerTerminal::new(4, 20, 1 << 20).unwrap();
        lines(&mut emu, 0, 20);
        let before = emu.snapshot().history();
        emu.resize(Size::new(6, 10));
        let after = emu.snapshot().history();
        assert!(
            after.oldest().unwrap() > before.newest,
            "{before:?} {after:?}"
        );
        let reply = emu.history(ask(before.newest, 5));
        assert!(reply.rows.is_empty(), "old names are gone");
    }

    fn row(name: u64, width: u16) -> HistoryRow {
        HistoryRow {
            name,
            flags: RowFlags::default(),
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
    const ALL: HistoryRequest = ask(10_000, u16::MAX);

    #[test]
    fn only_the_rows_asked_for_are_kept() {
        let mut cache = HistoryCache::default();
        let asked = ask(20, 2);
        let rows = (17..=22).map(|name| row(name, 4)).collect();
        assert_eq!(cache.insert(&reply(rows), asked, MARK, 20..=20), Some(2));
        assert!(cache.holds(19) && cache.holds(20));
        assert!(!cache.holds(18) && !cache.holds(21));
    }

    #[test]
    fn the_cache_keeps_only_rows_the_history_holds() {
        let mut cache = HistoryCache::default();
        let all = reply(vec![row(0, 5), row(1, 5), row(10_000, 5), row(10_001, 5)]);
        assert_eq!(cache.insert(&all, ALL, MARK, 1..=1), Some(2));
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
        let too_many_cells = reply((1..=100).map(|n| row(n, 1000)).collect());
        // A link no cell names: a hostile server could otherwise make the client keep links
        // nothing shows.
        let unnamed_link = HistoryRow {
            links: vec![WireLink {
                uri: "https://example.org".to_owned(),
                id: String::new(),
            }],
            ..row(3, 4)
        };
        for reply in [
            reply(vec![row(1, 3), too_wide]),
            reply(vec![row(1, 3), bad_link]),
            reply(vec![unnamed_link]),
            too_many_cells,
        ] {
            let mut cache = HistoryCache::default();
            assert_eq!(cache.insert(&reply, ALL, MARK, 1..=1), None);
            assert!(cache.is_empty());
        }
    }

    #[test]
    fn the_cache_is_bounded_by_bytes_dropping_the_rows_farthest_from_the_view() {
        // Wide rows, and narrow rows each carrying a reply's worth of links, every one named by a
        // cell: either way the memory held stays bounded, however many rows a hostile server sends.
        let links: Vec<WireLink> = (0..MAX_ROW_LINKS)
            .map(|n| WireLink {
                uri: format!(
                    "{n}{}",
                    "u".repeat(MAX_LINK_BYTES.div_euclid(MAX_ROW_LINKS * 2) - 4)
                ),
                id: String::new(),
            })
            .collect();
        for (width, per_reply, linked, replies) in [
            (1000, MAX_HISTORY_CELLS.div_euclid(1000), false, 100),
            (64, 1, true, 200),
        ] {
            let mut cache = HistoryCache::default();
            let mut name = 1_u64;
            for _ in 0..replies {
                let rows = (0..per_reply)
                    .map(|_| {
                        name += 1;
                        let mut row = row(name, width);
                        if linked {
                            let cell = row.runs[0].cell.clone();
                            row.runs = (1..=64)
                                .map(|link| Run {
                                    count: NonZeroU16::MIN,
                                    cell: WireCell {
                                        link,
                                        ..cell.clone()
                                    },
                                })
                                .collect();
                            row.links = links.clone();
                        }
                        row
                    })
                    .collect();
                let asked = ask(name, u16::try_from(per_reply).unwrap());
                cache.insert(&reply(rows), asked, MARK, 2..=2).unwrap();
                assert!(cache.bytes() <= HISTORY_CACHE_BYTES);
                // The rows just asked for are kept for the caller to read, however far.
                assert!(cache.holds(name));
            }
            assert!(cache.holds(2), "the row the view is on stays");
            assert!(
                !cache.holds(name - 2 * u64::try_from(per_reply).unwrap()),
                "the farthest went"
            );
        }
    }

    #[test]
    fn a_row_is_fitted_to_the_screen_without_halving_a_wide_glyph() {
        let mut cells = Cells::new(4);
        cells.set(2, CellRef::new("日", true, fux_vt::Attributes::default()));
        cells.set(3, CellRef::wide_continuation());
        let kept = KeptRow {
            cells: Arc::new(cells),
            flags: RowFlags::default(),
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
