//! The scrollback view (`Ctrl-^ [`): the server's history above the live screen, fetched by name as
//! the user scrolls, without I/O.
//!
//! The view is anchored to what it shows: new output scrolling into history moves the view up with
//! it, so the rows being read stay still while the screen below goes on. Its keys are less's and
//! tmux's: the arrows, `k`/`j`, Page Up/Down, `b`/`f`/space, `u`/`d`, Home/End, `g`/`G`, and the
//! mouse wheel; `q` or Escape leaves. `/` searches the history for text, older from the view's top,
//! fetching rows as it goes; `n` finds the next older match and `N` the next newer.

use std::time::{Duration, Instant};

use fux_vt::keys::decode::Input;
use fux_vt::keys::mouse::{MouseAction, MouseButton, MouseEvent};
use fux_vt::keys::{Direction, Key, KeyPress};

use crate::terminal::{
    HistoryCache, HistoryMark, HistoryReply, HistoryRequest, TerminalScreen, MAX_HISTORY_ROWS,
};

/// Most history requests a client has unanswered: enough to keep rows coming while one is
/// delivered, well within what the server takes.
const MAX_OUTSTANDING: usize = 2;

/// Rows the wheel scrolls a notch.
const WHEEL_ROWS: usize = 3;

/// How long the user must not have typed, nor a frame arrived, before the newest screenful of
/// history is fetched ahead of need.
pub const PREFETCH_IDLE: Duration = Duration::from_secs(2);

/// The history a client holds, and the view of it.
#[derive(Debug, Default)]
pub struct Scrollback {
    cache: HistoryCache,
    /// The rows scrolled back from the live screen, while the view is open.
    view: Option<usize>,
    /// The screen's height, as of the last request: how many rows the view shows.
    rows: u16,
    /// The history as the newest screen showed it.
    mark: HistoryMark,
    /// Requests sent and not answered. The server answers each, in any order, naming it; an
    /// answer to none of them is dropped.
    outstanding: Vec<HistoryRequest>,
    /// The id the next request takes.
    next_id: u64,
    /// A search of the history, while one is typed or under way.
    search: Option<Search>,
}

/// Most bytes of a search's text.
const MAX_QUERY: usize = 256;

/// Most rows one look at the held history reads before it waits for more to arrive or for the
/// next key: the search's work a call.
const SEARCH_STEP: usize = 4096;

/// A search of the history.
#[derive(Debug, Default)]
struct Search {
    /// The text sought, as typed.
    query: String,
    /// The text is being typed: keys go to it.
    typing: bool,
    /// Looking at older rows (else newer).
    older: bool,
    /// The next row to look at, while the search is under way.
    next: Option<u64>,
    /// The last search ended without a match.
    failed: bool,
}

impl Search {
    fn append(&mut self, text: &str) {
        for c in text.chars().filter(|c| !c.is_control()) {
            if self.query.len().saturating_add(c.len_utf8()) > MAX_QUERY {
                break;
            }
            self.query.push(c);
        }
    }

    fn editing_status(&self, cols: u16) -> String {
        let prefix = if cols >= 18 { "[koh] search: /" } else { "/" };
        // The painter reserves a surrounding space and clips by bytes. A UTF-8 byte bound
        // also conservatively fits wide characters; always keep the end being edited visible.
        let budget = usize::from(cols).saturating_sub(prefix.len().saturating_add(2));
        let start = self.query.len().saturating_sub(budget);
        let start = self.query.ceil_char_boundary(start);
        format!("{prefix}{}", self.query.get(start..).unwrap_or_default())
    }
}

impl Scrollback {
    /// Whether the view is open.
    pub const fn viewing(&self) -> bool {
        self.view.is_some()
    }

    /// Open the view, at the live screen.
    pub fn open(&mut self) {
        self.view = Some(0);
    }

    /// The rows held, for tests and the status line.
    pub const fn cache(&self) -> &HistoryCache {
        &self.cache
    }

    /// The rows scrolled back, if viewing.
    pub const fn offset(&self) -> Option<usize> {
        self.view
    }

    /// The newest screen showed the history at `mark`: drop the rows it no longer holds, and keep
    /// the view on the rows it showed.
    pub fn on_mark(&mut self, mark: HistoryMark) {
        if mark == self.mark {
            return;
        }
        let old = self.mark;
        self.mark = mark;
        self.cache.retain(mark);
        if let Some(offset) = self.view.as_mut() {
            // Rows that entered history since: the view moves up with them, unless it is at the
            // live screen, where it follows the output. A history laid out afresh (a resize) has
            // new names, and the view keeps its distance instead.
            let entered = mark
                .newest
                .checked_sub(old.newest)
                .filter(|_| old.len > 0 && mark.holds(old.newest));
            if *offset > 0 {
                if let Some(entered) = entered.and_then(|n| usize::try_from(n).ok()) {
                    *offset = offset.saturating_add(entered);
                }
            }
            *offset = (*offset).min(usize::try_from(mark.len).unwrap_or(usize::MAX));
        }
    }

    /// History rows arrived, the answer to the request outstanding that they name: keep the rows
    /// it asked for. An answer to none, and a malformed one, are dropped whole.
    pub fn on_reply(&mut self, reply: &HistoryReply) {
        let Some(at) = self.outstanding.iter().position(|r| r.id == reply.id) else {
            tracing::debug!("dropping history rows nobody asked for");
            return;
        };
        let asked = self.outstanding.swap_remove(at);
        let top = self.focus();
        let shown = top..=top.saturating_add(u64::from(self.rows));
        if self.cache.insert(reply, asked, self.mark, shown).is_none() {
            tracing::debug!("dropping malformed history rows");
        }
        self.advance_search();
    }

    /// Look further for the search's text through the rows held, from where it stands: until a
    /// match (the view then shows it at its top), the history's end (nothing found), or a row
    /// not held yet (asked for next).
    fn advance_search(&mut self) {
        let Some(oldest) = self.mark.oldest() else {
            return;
        };
        let newest = self.mark.newest;
        let Some(search) = self.search.as_mut().filter(|s| !s.typing) else {
            return;
        };
        let query = &search.query;
        for _ in 0..SEARCH_STEP {
            let Some(name) = search.next else {
                return;
            };
            if name < oldest || name > newest {
                search.next = None;
                search.failed = true;
                return;
            }
            let Some(row) = self.cache.get(name) else {
                return;
            };
            if row.text().contains(query) {
                search.next = None;
                search.failed = false;
                // At the view's top: `offset` rows up, the row the newest is at offset 1.
                self.view = usize::try_from(newest.saturating_sub(name).saturating_add(1)).ok();
                return;
            }
            search.next = if search.older {
                name.checked_sub(1)
            } else {
                name.checked_add(1)
            };
        }
    }

    /// Start looking for the search's text from the row before (`older`) or after the view's top.
    fn search_from_top(&mut self, older: bool) {
        let top = self.focus();
        // At the live screen the view's top is not history: the newest row is the first older.
        let at_live = self.view == Some(0);
        if let Some(search) = self.search.as_mut().filter(|s| !s.query.is_empty()) {
            search.typing = false;
            search.older = older;
            search.failed = false;
            search.next = match (older, at_live) {
                (true, true) => Some(top),
                (true, false) => top.checked_sub(1),
                (false, true) => None,
                (false, false) => top.checked_add(1),
            };
            search.failed = search.next.is_none();
        }
        self.advance_search();
    }

    /// The name of the row the view is about: the one at its top, or the newest.
    fn focus(&self) -> u64 {
        let back = self
            .view
            .and_then(|offset| u64::try_from(offset.saturating_sub(1)).ok())
            .unwrap_or(0);
        self.mark.newest.saturating_sub(back)
    }

    /// The next history request to send, if any: the rows the view shows and a page above them,
    /// or, idle and out of the view, the newest screenful. `rows` is the screen's height.
    pub fn next_request(&mut self, rows: u16, idle: bool) -> Option<HistoryRequest> {
        self.rows = rows;
        // A search that stopped on a row held, at the end of a step, goes on from it.
        self.advance_search();
        if self.outstanding.len() >= MAX_OUTSTANDING || self.mark.len == 0 {
            return None;
        }
        // A search under way asks for the rows it is waiting on first.
        if let Some((newest, count)) = self.search_request() {
            return Some(self.send(newest, count));
        }
        let rows_u64 = u64::from(rows);
        let (newest, span) = match self.view {
            Some(offset) => {
                // The view's top row, and a page above it; its bottom is the newest it shows.
                let top = self.focus();
                let bottom = top
                    .saturating_add(rows_u64.saturating_sub(1))
                    .min(self.mark.newest);
                (
                    bottom,
                    rows_u64.saturating_mul(2).min(
                        u64::try_from(offset)
                            .unwrap_or(u64::MAX)
                            .saturating_add(rows_u64),
                    ),
                )
            }
            None if idle => (self.mark.newest, rows_u64),
            None => return None,
        };
        let oldest = self.mark.oldest()?;
        let lowest = newest.saturating_sub(span.saturating_sub(1)).max(oldest);
        // The newest row missing, and the run of missing rows below it.
        let missing = (lowest..=newest)
            .rev()
            .find(|&name| !self.cache.holds(name) && !self.asked(name))?;
        let run = (lowest..=missing)
            .rev()
            .take_while(|&name| !self.cache.holds(name) && !self.asked(name))
            .take(usize::from(MAX_HISTORY_ROWS))
            .count();
        Some(self.send(missing, u16::try_from(run).unwrap_or(MAX_HISTORY_ROWS)))
    }

    /// A request for `count` rows up to `newest`, sent: it is kept until its answer.
    fn send(&mut self, newest: u64, count: u16) -> HistoryRequest {
        let request = HistoryRequest {
            id: self.next_id,
            newest,
            count,
        };
        self.next_id = self.next_id.wrapping_add(1);
        self.outstanding.push(request);
        request
    }

    /// The rows a search waits on, newest and count, if it does and they are not asked for.
    fn search_request(&self) -> Option<(u64, u16)> {
        let search = self.search.as_ref()?;
        let name = search.next?;
        if self.cache.holds(name) || self.asked(name) {
            return None;
        }
        let oldest = self.mark.oldest()?;
        if search.older {
            let count = name.saturating_sub(oldest).saturating_add(1);
            Some((
                name,
                u16::try_from(count.min(u64::from(MAX_HISTORY_ROWS))).ok()?,
            ))
        } else {
            let newest = name
                .saturating_add(u64::from(MAX_HISTORY_ROWS).saturating_sub(1))
                .min(self.mark.newest);
            Some((
                newest,
                u16::try_from(newest.saturating_sub(name).saturating_add(1)).ok()?,
            ))
        }
    }

    /// Whether an unanswered request covers the row named `name`.
    fn asked(&self, name: u64) -> bool {
        self.outstanding.iter().any(|asked| asked.covers(name))
    }

    /// The connection was lost: requests on it will not be answered.
    pub fn forget_requests(&mut self) {
        self.outstanding.clear();
    }

    /// A new connection: the history held is the last server session's, and the new one may be
    /// another (a restarted server, an expired session), whose rows reuse the same names. It goes,
    /// and the new connection's frames say the history again; the view stays open, and a search
    /// under way, whose place is a row of the old names, ends.
    pub fn reconnected(&mut self) {
        self.cache = HistoryCache::default();
        self.mark = HistoryMark::default();
        self.outstanding.clear();
        self.search = None;
    }

    /// The screen to show for `live`: `live` scrolled back, while viewing.
    pub fn shown(&self, live: &TerminalScreen) -> Option<TerminalScreen> {
        self.view
            .map(|offset| live.scrolled_back(&self.cache, offset))
    }

    /// The status line while viewing.
    pub fn status(&self) -> Option<String> {
        self.status_at(u16::MAX)
    }

    pub(crate) fn status_at(&self, cols: u16) -> Option<String> {
        let offset = self.view?;
        let len = self.mark.len;
        Some(match &self.search {
            Some(search) if search.typing => search.editing_status(cols),
            Some(search) if search.next.is_some() => {
                format!(
                    "[koh] scrollback {offset}/{len} — searching for {:?}…",
                    search.query
                )
            }
            Some(search) if search.failed => {
                format!(
                    "[koh] scrollback {offset}/{len} — {:?} not found",
                    search.query
                )
            }
            Some(_) | None => format!(
                "[koh] scrollback {offset}/{len} — arrows, PgUp/PgDn, wheel; / searches; q leaves"
            ),
        })
    }

    /// Input decoded while viewing, for a screen `rows` high: each key in its legacy form (one
    /// form of each, whatever the user's terminal sent), the wheel, and a paste into a search.
    /// Input after a key that leaves the view is not the view's.
    pub fn on_events(&mut self, inputs: &[Input], rows: u16) {
        for input in inputs {
            if !self.viewing() {
                return;
            }
            match input {
                Input::Key(stroke) => self.on_key(stroke.press, rows),
                Input::Mouse(MouseEvent {
                    action: MouseAction::Press,
                    button: Some(button),
                    ..
                }) => match button {
                    MouseButton::WheelUp => self.step(Step::Up(WHEEL_ROWS)),
                    MouseButton::WheelDown => self.step(Step::Down(WHEEL_ROWS)),
                    MouseButton::Left
                    | MouseButton::Middle
                    | MouseButton::Right
                    | MouseButton::WheelLeft
                    | MouseButton::WheelRight
                    | MouseButton::Back
                    | MouseButton::Forward => {}
                },
                Input::Paste(text) => {
                    if let Some(search) = self.search.as_mut().filter(|s| s.typing) {
                        search.append(text);
                    }
                }
                Input::Mouse(_)
                | Input::PasteTooLong
                | Input::FocusIn
                | Input::FocusOut
                | Input::Reply(_) => {}
            }
        }
    }

    /// Act on the key the decoder already resolved; escape sequences never enter this layer.
    fn on_key(&mut self, press: KeyPress, rows: u16) {
        let KeyPress { key, mods } = press;
        if mods.alt
            || ((!mods.is_empty())
                && matches!(
                    key,
                    Key::Arrow(_) | Key::Home | Key::End | Key::PageUp | Key::PageDown
                ))
        {
            return;
        }
        if let Some(search) = self.search.as_mut().filter(|s| s.typing) {
            match key {
                Key::Escape => self.search = None,
                Key::Enter => self.search_from_top(true),
                Key::Backspace => {
                    search.query.pop();
                }
                Key::Char('c' | '[') if mods.ctrl => self.search = None,
                Key::Char('h' | '?') if mods.ctrl => {
                    search.query.pop();
                }
                Key::Char('m' | 'j') if mods.ctrl => self.search_from_top(true),
                Key::Char(c) if !mods.ctrl => {
                    let mut utf8 = [0; 4];
                    search.append(c.encode_utf8(&mut utf8));
                }
                Key::Char(_)
                | Key::Tab
                | Key::Delete
                | Key::Insert
                | Key::Arrow(_)
                | Key::Home
                | Key::End
                | Key::PageUp
                | Key::PageDown
                | Key::F(_) => {}
            }
            return;
        }
        let page = usize::from(rows.saturating_sub(1)).max(1);
        let half = page.div_euclid(2).max(1);
        let step = match key {
            Key::Char('c' | '[') if mods.ctrl => return self.leave(),
            Key::Char('p' | 'y') if mods.ctrl => Step::Up(1),
            Key::Char('n' | 'e' | 'm') if mods.ctrl => Step::Down(1),
            Key::Char('b') if mods.ctrl => Step::Up(page),
            Key::Char('f') if mods.ctrl => Step::Down(page),
            Key::Char('u') if mods.ctrl => Step::Up(half),
            Key::Char('d') if mods.ctrl => Step::Down(half),
            Key::Char(_) if mods.ctrl => Step::None,
            Key::Char('q') | Key::Escape => return self.leave(),
            Key::Char('/') => {
                self.search = Some(Search {
                    typing: true,
                    ..Search::default()
                });
                Step::None
            }
            Key::Char('n' | 'N') => {
                self.search_from_top(key == Key::Char('n'));
                Step::None
            }
            Key::Char('k' | 'y') | Key::Arrow(Direction::Up) => Step::Up(1),
            Key::Char('j' | 'e') | Key::Enter | Key::Arrow(Direction::Down) => Step::Down(1),
            Key::Char('b') | Key::PageUp => Step::Up(page),
            Key::Char('f' | ' ') | Key::PageDown => Step::Down(page),
            Key::Char('u') => Step::Up(half),
            Key::Char('d') => Step::Down(half),
            Key::Char('g') | Key::Home => Step::Top,
            Key::Char('G') | Key::End => Step::Bottom,
            Key::Char(_)
            | Key::Tab
            | Key::Backspace
            | Key::Delete
            | Key::Insert
            | Key::Arrow(Direction::Left | Direction::Right)
            | Key::F(_) => Step::None,
        };
        self.step(step);
    }

    fn leave(&mut self) {
        self.view = None;
        self.search = None;
    }

    fn step(&mut self, step: Step) {
        let Some(offset) = self.view.as_mut() else {
            return;
        };
        let most = usize::try_from(self.mark.len).unwrap_or(usize::MAX);
        *offset = match step {
            Step::Up(n) => offset.saturating_add(n).min(most),
            Step::Down(n) => offset.saturating_sub(n),
            Step::Top => most,
            Step::Bottom => 0,
            Step::None => *offset,
        };
    }

    /// Whether the client was idle long enough to fetch ahead: nothing typed, and no frame, since
    /// `PREFETCH_IDLE` before `now`.
    pub fn idle(now: Instant, last_activity: Option<Instant>) -> bool {
        last_activity.is_none_or(|at| now.saturating_duration_since(at) >= PREFETCH_IDLE)
    }
}

/// A move of the view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Up(usize),
    Down(usize),
    Top,
    Bottom,
    None,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_keeps_whole_characters_at_capacity_for_keys_and_paste() {
        for paste in [false, true] {
            let mut view = viewing(100);
            view.on_keys(b"/", 25);
            view.on_keys(&vec![b'a'; 255], 25);
            if paste {
                view.on_events(&[Input::Paste("é".into())], 25);
            } else {
                view.on_keys("é".as_bytes(), 25);
            }
            assert_eq!(view.search.as_ref().unwrap().query, "a".repeat(255));
            view.on_keys(b"\x7f", 25);
            view.on_keys("é".as_bytes(), 25);
            assert_eq!(
                view.search.as_ref().unwrap().query,
                format!("{}é", "a".repeat(254))
            );
            let status = view.status_at(30).unwrap();
            assert!(status.ends_with('é'));
            assert!(status.len() <= 28);
            view.on_keys(b"\x7f", 25);
            assert_eq!(view.search.as_ref().unwrap().query, "a".repeat(254));
            view.on_keys(b"\x03", 25);
            assert!(view.search.is_none());
            assert!(view.viewing());
        }
    }

    #[test]
    fn decoded_control_aliases_keep_their_legacy_navigation_and_editing_behavior() {
        for editing in [false, true] {
            for (byte, character) in [(b'\r', 'm'), (0x1b, '['), (0x7f, '?')] {
                let mut legacy = viewing(100);
                let mut decoded = viewing(100);
                for view in [&mut legacy, &mut decoded] {
                    view.on_keys(b"kk", 25);
                    if editing {
                        view.on_keys(b"/query", 25);
                    }
                }
                legacy.on_keys(&[byte], 25);
                decoded.on_events(
                    &[Input::Key(
                        KeyPress::new(Key::Char(character), fux_vt::keys::Modifiers::CTRL).into(),
                    )],
                    25,
                );
                assert_eq!(decoded.viewing(), legacy.viewing());
                assert_eq!(decoded.offset(), legacy.offset());
                assert_eq!(decoded.status(), legacy.status());
            }
        }
    }

    impl Scrollback {
        fn on_keys(&mut self, bytes: &[u8], rows: u16) {
            let mut decoder = fux_vt::keys::decode::Decoder::default();
            let mut inputs = Vec::new();
            decoder.bytes(bytes, &mut inputs);
            decoder.timeout(&mut inputs);
            self.on_events(&inputs, rows);
        }
    }

    fn viewing(len: u32) -> Scrollback {
        let mut s = Scrollback::default();
        s.on_mark(HistoryMark { newest: 1000, len });
        s.open();
        s
    }

    #[test]
    fn keys_move_the_view_within_the_history() {
        let mut s = viewing(100);
        let rows = 25;
        let press = |s: &mut Scrollback, keys: &[u8]| {
            s.on_keys(keys, rows);
            s.offset().unwrap()
        };
        assert_eq!(press(&mut s, b"k"), 1);
        assert_eq!(press(&mut s, b"\x1b[A\x1bOA"), 3);
        assert_eq!(press(&mut s, b"\x1b[5~"), 27);
        assert_eq!(press(&mut s, b"\x1b[6~j"), 2);
        // Mouse reports come decoded.
        let decoded = |s: &mut Scrollback, bytes: &[u8]| {
            let mut inputs = Vec::new();
            fux_vt::keys::decode::Decoder::default().bytes(bytes, &mut inputs);
            s.on_events(&inputs, rows);
            s.offset().unwrap()
        };
        assert_eq!(decoded(&mut s, b"\x1b[<64;10;5M"), 5, "the wheel up");
        assert_eq!(decoded(&mut s, b"\x1b[<65;10;5M"), 2, "the wheel down");
        assert_eq!(
            decoded(&mut s, b"\x1b[<0;10;5M\x1b[<0;10;5m"),
            2,
            "a click does nothing"
        );
        assert_eq!(
            decoded(&mut s, b"\x1b[5~\x1b[1;5A"),
            26,
            "keys come decoded too"
        );
        assert_eq!(decoded(&mut s, b"\x1b[6~"), 2);
        assert_eq!(press(&mut s, b"g"), 100, "the top is the oldest row");
        assert_eq!(press(&mut s, b"k"), 100, "and no further");
        assert_eq!(press(&mut s, b"u"), 100);
        assert_eq!(press(&mut s, b"d"), 88);
        assert_eq!(press(&mut s, b"\x1b[F"), 0);
        assert_eq!(press(&mut s, b"j"), 0, "the live screen is the bottom");
        assert_eq!(press(&mut s, b"x\x1bx"), 0, "other keys do nothing");
    }

    #[test]
    fn an_escape_sequence_split_across_reads_is_read_whole() {
        let mut s = viewing(100);
        let mut decoder = fux_vt::keys::decode::Decoder::default();
        for bytes in [&b"\x1b["[..], b"5", b"~"] {
            let mut inputs = Vec::new();
            decoder.bytes(bytes, &mut inputs);
            s.on_events(&inputs, 25);
        }
        assert_eq!(s.offset(), Some(24));
    }

    #[test]
    fn q_ctrl_c_or_a_lone_escape_leaves() {
        for keys in [&b"q"[..], b"\x03", b"\x1b", b"kkq"] {
            let mut s = viewing(100);
            s.on_keys(keys, 25);
            assert!(!s.viewing(), "{keys:?}");
        }
    }

    #[test]
    fn the_view_asks_for_what_it_shows_and_a_page_above_two_requests_at_most() {
        let mut s = viewing(1000);
        s.on_keys(b"\x1b[5~\x1b[5~", 25);
        assert_eq!(s.offset(), Some(48));
        let first = s.next_request(25, false).unwrap();
        // The view's top is 48 rows up: rows 953..=977 shown, a page above from 928.
        assert_eq!(first.newest, 977);
        assert_eq!(first.count, 50);
        assert_eq!(s.next_request(25, false), None, "nothing left uncovered");
        s.on_keys(b"g", 25);
        assert!(s.next_request(25, false).is_some());
        assert_eq!(s.next_request(25, false), None, "two requests at most");
        s.on_reply(&HistoryReply::default());
        assert!(
            s.next_request(25, false).is_none(),
            "the top page is already asked for"
        );
    }

    #[test]
    fn out_of_the_view_only_an_idle_client_fetches_ahead() {
        let mut s = Scrollback::default();
        s.on_mark(HistoryMark {
            newest: 500,
            len: 500,
        });
        assert_eq!(s.next_request(25, false), None);
        let ahead = s.next_request(25, true).unwrap();
        assert_eq!(
            (ahead.newest, ahead.count),
            (500, 25),
            "one screenful, the newest"
        );
        assert_eq!(s.next_request(25, true), None);
    }

    #[test]
    fn the_view_moves_with_rows_entering_history_unless_at_the_live_screen() {
        let mut s = viewing(100);
        s.on_mark(HistoryMark {
            newest: 1003,
            len: 103,
        });
        assert_eq!(
            s.offset(),
            Some(0),
            "at the live screen it follows the output"
        );
        s.on_keys(b"kk", 25);
        s.on_mark(HistoryMark {
            newest: 1010,
            len: 110,
        });
        assert_eq!(s.offset(), Some(9));
        // A history named afresh (a resize): the view keeps its distance, within the history.
        s.on_mark(HistoryMark {
            newest: 5000,
            len: 4,
        });
        assert_eq!(s.offset(), Some(4));
    }

    /// The rows `request` asks for, each `width` cells of `x`, but the row named `needle` of `y`.
    fn answer(request: HistoryRequest, width: u16, needle: u64) -> HistoryReply {
        use crate::terminal::{CellKind, CellText, HistoryRow, Run, WireCell, WireColor};
        let row = |name: u64| HistoryRow {
            name,
            wrapped: false,
            runs: vec![Run {
                count: std::num::NonZeroU16::new(width).unwrap(),
                cell: WireCell {
                    text: CellText::new(if name == needle { "y" } else { "x" }).unwrap(),
                    kind: CellKind::Narrow,
                    fg: WireColor::Default,
                    bg: WireColor::Default,
                    underline_color: WireColor::Default,
                    style: crate::terminal::WireStyle::default(),
                    link: 0,
                },
            }],
            links: Vec::new(),
        };
        let oldest = request
            .newest
            .saturating_sub(u64::from(request.count).saturating_sub(1));
        HistoryReply {
            id: request.id,
            rows: (oldest..=request.newest).map(row).collect(),
        }
    }

    #[test]
    fn replies_pair_with_their_requests_by_id_in_any_order() {
        // Two requests out; their answers come the other way round, with one nobody asked for
        // between. Each keeps its own rows, and the client goes on asking.
        let mut s = viewing(1000);
        s.on_keys(b"g", 25);
        let first = s.next_request(25, false).unwrap();
        s.on_keys(b"\x1b[F", 25);
        s.on_keys(&b"\x1b[5~".repeat(10), 25);
        let second = s.next_request(25, false).unwrap();
        assert_eq!(s.next_request(25, false), None, "two out");
        s.on_reply(&answer(second, 10, 0));
        s.on_reply(&HistoryReply {
            id: 99,
            ..answer(first, 10, 0)
        });
        assert!(
            !s.cache().holds(first.newest),
            "an answer to nothing is dropped"
        );
        s.on_reply(&answer(first, 10, 0));
        assert!(s.cache().holds(first.newest) && s.cache().holds(second.newest));
        // A lost answer would have held a slot; an empty one frees it.
        s.on_keys(&b"\x1b[5~".repeat(10), 25);
        let third = s.next_request(25, false).unwrap();
        s.on_reply(&third.none());
        assert!(s.next_request(25, false).is_some(), "not stalled");
    }

    #[test]
    fn a_search_through_more_history_than_the_cache_holds_finishes() {
        // Each row takes about 5.6 kB, so 30 000 are over twice the cache: the rows a search
        // fetches are the farthest from the view, and were evicted before it read them, for ever.
        const ROWS: u32 = 30_000;
        const NEWEST: u64 = 100_000;
        let mut s = Scrollback::default();
        s.on_mark(HistoryMark {
            newest: NEWEST,
            len: ROWS,
        });
        s.open();
        let needle = NEWEST - u64::from(ROWS) + 5;
        s.on_keys(b"/y\r", 25);
        for _ in 0..1000 {
            let Some(request) = s.next_request(25, false) else {
                break;
            };
            s.on_reply(&answer(request, 250, needle));
        }
        let status = s.status().unwrap();
        assert!(!status.contains("searching"), "{status}");
        assert!(!status.contains("not found"), "{status}");
        assert_eq!(s.offset(), usize::try_from(NEWEST - needle + 1).ok());
    }
}
