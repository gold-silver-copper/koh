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
use fux_vt::keys::encode::{key_bytes, KeyMode};
use fux_vt::keys::mouse::{MouseAction, MouseButton, MouseEvent};

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

/// What a key read in the view does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewKeys {
    /// The view stays.
    Stay,
    /// The user left the view.
    Leave,
}

/// The history a client holds, and the view of it.
#[derive(Debug, Default)]
pub struct Scrollback {
    cache: HistoryCache,
    /// The rows scrolled back from the live screen, while the view is open.
    view: Option<usize>,
    /// The history as the newest screen showed it.
    mark: HistoryMark,
    /// Requests sent and not answered, oldest first: the server answers in order.
    outstanding: Vec<HistoryRequest>,
    /// The bytes of an escape sequence split across reads.
    partial: Vec<u8>,
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
    query: Vec<u8>,
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
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.query).into_owned()
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
        self.partial.clear();
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

    /// History rows arrived: keep them. A malformed answer is dropped whole.
    pub fn on_reply(&mut self, reply: &HistoryReply) {
        if !self.outstanding.is_empty() {
            self.outstanding.remove(0);
        }
        let near = self.focus();
        if self.cache.insert(reply, self.mark, near).is_none() {
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
        let query = search.text();
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
            if row.text().contains(&query) {
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
        if self.outstanding.len() >= MAX_OUTSTANDING || self.mark.len == 0 {
            return None;
        }
        // A search under way asks for the rows it is waiting on first.
        if let Some(request) = self.search_request() {
            self.outstanding.push(request);
            return Some(request);
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
        let request = HistoryRequest {
            newest: missing,
            count: u16::try_from(run).unwrap_or(MAX_HISTORY_ROWS),
        };
        self.outstanding.push(request);
        Some(request)
    }

    /// The rows a search waits on, if it does and they are not asked for.
    fn search_request(&self) -> Option<HistoryRequest> {
        let search = self.search.as_ref()?;
        let name = search.next?;
        if self.cache.holds(name) || self.asked(name) {
            return None;
        }
        let oldest = self.mark.oldest()?;
        if search.older {
            let count = name.saturating_sub(oldest).saturating_add(1);
            Some(HistoryRequest {
                newest: name,
                count: u16::try_from(count.min(u64::from(MAX_HISTORY_ROWS))).ok()?,
            })
        } else {
            let newest = name
                .saturating_add(u64::from(MAX_HISTORY_ROWS).saturating_sub(1))
                .min(self.mark.newest);
            Some(HistoryRequest {
                newest,
                count: u16::try_from(newest.saturating_sub(name).saturating_add(1)).ok()?,
            })
        }
    }

    /// Whether an unanswered request covers the row named `name`.
    fn asked(&self, name: u64) -> bool {
        self.outstanding.iter().any(|request| {
            name <= request.newest && request.newest.saturating_sub(name) < u64::from(request.count)
        })
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
        let offset = self.view?;
        let len = self.mark.len;
        Some(match &self.search {
            Some(search) if search.typing => format!("[koh] search: /{}", search.text()),
            Some(search) if search.next.is_some() => {
                format!(
                    "[koh] scrollback {offset}/{len} — searching for {:?}…",
                    search.text()
                )
            }
            Some(search) if search.failed => {
                format!(
                    "[koh] scrollback {offset}/{len} — {:?} not found",
                    search.text()
                )
            }
            Some(_) | None => format!(
                "[koh] scrollback {offset}/{len} — arrows, PgUp/PgDn, wheel; / searches; q leaves"
            ),
        })
    }

    /// Input decoded while viewing, for a screen `rows` high: each key in its legacy form (one
    /// form of each, whatever the user's terminal sent), the wheel, and a paste into a search.
    pub fn on_events(&mut self, inputs: &[Input], rows: u16) -> ViewKeys {
        for input in inputs {
            match input {
                Input::Key(stroke) => {
                    let mut bytes = Vec::with_capacity(8);
                    key_bytes(stroke.press.into(), KeyMode::legacy(false), &mut bytes);
                    if self.on_keys(&bytes, rows) == ViewKeys::Leave {
                        return ViewKeys::Leave;
                    }
                }
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
                        for c in text.chars().filter(|c| !c.is_control()) {
                            let mut utf8 = [0; 4];
                            let c = c.encode_utf8(&mut utf8).as_bytes();
                            if search.query.len().saturating_add(c.len()) > MAX_QUERY {
                                break;
                            }
                            search.query.extend_from_slice(c);
                        }
                    }
                }
                Input::Mouse(_)
                | Input::PasteTooLong
                | Input::FocusIn
                | Input::FocusOut
                | Input::Reply(_) => {}
            }
        }
        ViewKeys::Stay
    }

    /// Keys typed while viewing, as legacy bytes, for a screen `rows` high.
    fn on_keys(&mut self, bytes: &[u8], rows: u16) -> ViewKeys {
        let mut input = std::mem::take(&mut self.partial);
        input.extend_from_slice(bytes);
        let page = usize::from(rows.saturating_sub(1)).max(1);
        let half = page.div_euclid(2).max(1);
        let mut rest = input.as_slice();
        while let Some((&byte, tail)) = rest.split_first() {
            if let Some(search) = self.search.as_mut().filter(|s| s.typing) {
                match byte {
                    b'\r' | b'\n' => self.search_from_top(true),
                    0x7f | 0x08 => {
                        // Back a character, its UTF-8 continuation bytes with it.
                        while search
                            .query
                            .pop()
                            .is_some_and(|b| (0x80..=0xbf).contains(&b))
                        {}
                    }
                    0x1b | 0x03 => self.search = None,
                    byte if byte >= 0x20 && search.query.len() < MAX_QUERY => {
                        search.query.push(byte);
                    }
                    _ => {}
                }
                rest = tail;
                continue;
            }
            let (step, used) = match byte {
                b'q' | 0x03 => return self.leave(),
                b'/' => {
                    self.search = Some(Search {
                        typing: true,
                        ..Search::default()
                    });
                    (Step::None, 1)
                }
                b'n' => {
                    self.search_from_top(true);
                    (Step::None, 1)
                }
                b'N' => {
                    self.search_from_top(false);
                    (Step::None, 1)
                }
                0x1b => match parse_escape(rest) {
                    Escape::Partial if rest.len() == 1 => return self.leave(),
                    Escape::Partial => {
                        self.partial = rest.to_vec();
                        break;
                    }
                    Escape::Key(step, used) => (step, used),
                },
                b'k' | b'y' | 0x10 | 0x19 => (Step::Up(1), 1),
                b'j' | b'e' | 0x0e | 0x05 | b'\r' => (Step::Down(1), 1),
                b'b' | 0x02 => (Step::Up(page), 1),
                b'f' | b' ' | 0x06 => (Step::Down(page), 1),
                b'u' | 0x15 => (Step::Up(half), 1),
                b'd' | 0x04 => (Step::Down(half), 1),
                b'g' => (Step::Top, 1),
                b'G' => (Step::Bottom, 1),
                _ => (Step::None, 1),
            };
            let step = match step {
                Step::PageUp => Step::Up(page),
                Step::PageDown => Step::Down(page),
                step @ (Step::Up(_) | Step::Down(_) | Step::Top | Step::Bottom | Step::None) => {
                    step
                }
            };
            self.step(step);
            rest = rest.get(used..).unwrap_or(tail);
        }
        ViewKeys::Stay
    }

    fn leave(&mut self) -> ViewKeys {
        self.view = None;
        self.partial.clear();
        self.search = None;
        ViewKeys::Leave
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
            Step::PageUp | Step::PageDown | Step::None => *offset,
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
    /// A page, which only the view knows.
    PageUp,
    PageDown,
    Top,
    Bottom,
    None,
}

/// An escape sequence read in the view.
enum Escape {
    /// Not complete in what was read.
    Partial,
    /// What it does, and its length.
    Key(Step, usize),
}

/// The escape sequence at the start of `bytes` (which starts with ESC).
fn parse_escape(bytes: &[u8]) -> Escape {
    match bytes.get(1) {
        None => Escape::Partial,
        Some(b'O') => match bytes.get(2) {
            None => Escape::Partial,
            Some(b'A') => Escape::Key(Step::Up(1), 3),
            Some(b'B') => Escape::Key(Step::Down(1), 3),
            Some(b'H') => Escape::Key(Step::Top, 3),
            Some(b'F') => Escape::Key(Step::Bottom, 3),
            Some(_) => Escape::Key(Step::None, 3),
        },
        Some(b'[') => {
            // Parameters and intermediates, then a final byte.
            let Some(len) = bytes
                .iter()
                .skip(2)
                .position(|b| (0x40..=0x7e).contains(b))
                .map(|at| at.saturating_add(3))
            else {
                // A sequence longer than any key is not one; drop it.
                return if bytes.len() > 32 {
                    Escape::Key(Step::None, bytes.len())
                } else {
                    Escape::Partial
                };
            };
            let body = bytes.get(2..len.saturating_sub(1)).unwrap_or_default();
            let last = bytes.get(len.saturating_sub(1)).copied().unwrap_or(0);
            let step = match (body, last) {
                (b"", b'A') => Step::Up(1),
                (b"", b'B') => Step::Down(1),
                (b"" | b"1", b'H') | (b"1" | b"7", b'~') => Step::Top,
                (b"" | b"1", b'F') | (b"4" | b"8", b'~') => Step::Bottom,
                (b"5", b'~') => Step::PageUp,
                (b"6", b'~') => Step::PageDown,
                _ => Step::None,
            };
            Escape::Key(step, len)
        }
        // Alt and a key, or a lone ESC followed by more keys.
        Some(_) => Escape::Key(Step::None, 2),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            assert_eq!(s.on_keys(keys, rows), ViewKeys::Stay);
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
            assert_eq!(s.on_events(&inputs, rows), ViewKeys::Stay);
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
        assert_eq!(s.on_keys(b"\x1b[", 25), ViewKeys::Stay);
        assert_eq!(s.on_keys(b"5", 25), ViewKeys::Stay);
        assert_eq!(s.on_keys(b"~", 25), ViewKeys::Stay);
        assert_eq!(s.offset(), Some(24));
    }

    #[test]
    fn q_ctrl_c_or_a_lone_escape_leaves() {
        for keys in [&b"q"[..], b"\x03", b"\x1b", b"kkq"] {
            let mut s = viewing(100);
            assert_eq!(s.on_keys(keys, 25), ViewKeys::Leave, "{keys:?}");
            assert!(!s.viewing());
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
}
