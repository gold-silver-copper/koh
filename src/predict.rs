//! Local-echo prediction: the client guesses what each keystroke does to the screen and shows it at
//! once, then confirms or corrects it when the server's frame arrives.
//!
//! Guesses are grouped in epochs, confirmed by the server's echo-ack, so input a program does not
//! echo (a password) is never shown. It predicts printable ASCII, backspace, CR/LF, left/right
//! arrows and whole UTF-8 graphemes, wide ones included; anything else opens a new epoch and waits
//! for the server. A wrong guess is reconciled away, never left on screen. The renderer draws an
//! [`Overlay`].

use std::collections::{BTreeMap, BTreeSet};

use fux_vt::keys::encode::{key_bytes, KeyMode};
use fux_vt::keys::KeyPress;
use fux_vt::Color;

use serde::{Deserialize, Serialize};
use unicode_width::UnicodeWidthStr;

/// How the program's PTY takes typed keys: whether the kernel echoes them, and edits lines.
///
/// Line mode without echo is a password prompt (`getpass`, `read -s`, sudo, ssh,
/// passwd); neither is a line editor or a full-screen program, which echo for themselves. Here
/// for the same reason as [`Size`]; [`terminal`](crate::terminal) re-exports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TtyModes {
    pub echo: bool,
    pub line: bool,
}

impl TtyModes {
    /// A password prompt: lines read without echo. Nothing typed may be shown.
    pub const fn password(self) -> bool {
        self.line && !self.echo
    }
}

/// A terminal's geometry: `rows` lines of `cols` cells each.
///
/// Here because the predictor imports nothing from `crate::`; [`terminal`](crate::terminal)
/// re-exports it. On the wire it is its two `u16`s, rows first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Size {
    pub rows: u16,
    pub cols: u16,
}

impl Size {
    pub const fn new(rows: u16, cols: u16) -> Self {
        Self { rows, cols }
    }
}

/// One cell as the predictor sees it: the glyph (empty for a blank or a wide-glyph continuation),
/// its colours, and whether it is either half of a wide glyph.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CellView<'a> {
    pub contents: &'a str,
    pub fg: Color,
    pub bg: Color,
    /// The left half of a wide glyph, whose right half is the next cell.
    pub wide: bool,
    /// The right half of a wide glyph.
    pub continuation: bool,
}

/// The screen the predictor reconciles against: the client's grid, or a test's. A trait, so
/// `predict` imports nothing from `crate::` (CI checks).
pub trait ScreenView {
    fn size(&self) -> Size;
    /// The cursor as `(row, col)`, 0-indexed.
    fn cursor_position(&self) -> (u16, u16);
    /// The cell at `(row, col)`, or `None` when out of bounds.
    fn cell(&self, row: u16, col: u16) -> Option<CellView<'_>>;
}

/// When predictions are drawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayPreference {
    /// Always render predictions.
    Always,
    /// Never predict (the plain, non-speculative path).
    Never,
}

/// A speculative cell for the renderer to draw, as is, on top of the authoritative grid.
///
/// Only concrete guesses become one: a cell the predictor knows changed but not to what is left
/// out of the [`Overlay`], so the real cell beneath shows. A wide glyph is predicted in two cells:
/// the glyph, and the cell to its right `covered`, which the glyph draws over.
#[derive(Clone, Copy, Debug)]
pub struct PredictedCell<'a> {
    /// The predicted glyph, borrowed from the engine; empty for a blank shifted in by an insert or
    /// a backspace, and for a covered cell.
    pub glyph: &'a str,
    pub fg: Color,
    pub bg: Color,
    /// The right half of the predicted wide glyph to its left: nothing of its own to draw.
    pub covered: bool,
}

/// The render-facing snapshot of current predictions, borrowing its glyphs from the
/// [`PredictionEngine`] it came from.
#[derive(Default, Debug)]
pub struct Overlay<'a> {
    cells: BTreeMap<(u16, u16), PredictedCell<'a>>,
    cursor: Option<(u16, u16)>,
}

impl<'a> Overlay<'a> {
    pub fn empty() -> Self {
        Self::default()
    }
    /// The predicted cell at `(row, col)`, if any.
    pub fn cell(&self, row: u16, col: u16) -> Option<&PredictedCell<'a>> {
        self.cells.get(&(row, col))
    }
    /// An overlay of exactly `cells` and `cursor`, for tests of what draws it.
    #[cfg(test)]
    pub(crate) fn of(
        cells: impl IntoIterator<Item = ((u16, u16), PredictedCell<'a>)>,
        cursor: Option<(u16, u16)>,
    ) -> Self {
        Self {
            cells: cells.into_iter().collect(),
            cursor,
        }
    }
    /// Every predicted cell, in `(row, col)` order.
    pub fn cells(&self) -> impl Iterator<Item = ((u16, u16), &PredictedCell<'a>)> + '_ {
        self.cells.iter().map(|(&at, cell)| (at, cell))
    }
    /// The predicted cursor position `(row, col)`, if any.
    pub fn cursor(&self) -> Option<(u16, u16)> {
        self.cursor
    }
    pub fn is_empty(&self) -> bool {
        self.cells.is_empty() && self.cursor.is_none()
    }
}

/// What a prediction says a cell shows.
#[derive(Clone)]
struct Guess {
    glyph: String,
    fg: Color,
    bg: Color,
    /// Changed, but not known to what: never drawn.
    unknown: bool,
    /// The glyph is wide: the cell to its right is `covered`.
    wide: bool,
    /// The right half of the wide glyph to its left.
    covered: bool,
}

impl Guess {
    /// `glyph`, narrow or wide, in `fg` on `bg`.
    fn glyph(glyph: String, wide: bool, fg: Color, bg: Color) -> Self {
        Self {
            glyph,
            fg,
            bg,
            unknown: false,
            wide,
            covered: false,
        }
    }

    /// The right half of a wide glyph in `fg` on `bg`.
    fn covered(fg: Color, bg: Color) -> Self {
        Self {
            covered: true,
            ..Self::glyph(String::new(), false, fg, bg)
        }
    }

    /// A cell that changed to something not known, keeping `fg` and `bg`.
    fn unknown(fg: Color, bg: Color) -> Self {
        Self {
            unknown: true,
            ..Self::glyph(String::new(), false, fg, bg)
        }
    }
}

#[derive(Clone)]
struct PredCell {
    expiration_frame: u64,
    tentative_epoch: u64,
    glyph: String,
    fg: Color,
    bg: Color,
    /// The glyph this overwrote, so a rewrite back to it cannot confirm an epoch. `None` for an
    /// `unknown` cell, which never grades against it.
    original_contents: Option<String>,
    /// Changed, but not known to what: never drawn.
    unknown: bool,
    /// The glyph is wide: the next cell is `covered`.
    wide: bool,
    /// The right half of the wide glyph to its left: it confirms nothing, and is right when the
    /// server shows a wide glyph's right half there.
    covered: bool,
}

#[derive(Clone)]
struct PredCursor {
    expiration_frame: u64,
    tentative_epoch: u64,
    row: u16,
    col: u16,
}

#[derive(PartialEq, Eq)]
enum Validity {
    Pending,
    Correct,
    CorrectNoCredit,
    IncorrectOrExpired,
}

/// Where typed input is in an escape sequence, so its bytes are not predicted as glyphs.
#[derive(PartialEq, Eq, Clone, Copy)]
enum EscState {
    /// Not mid-escape.
    Ground,
    /// Saw `ESC`.
    Esc,
    /// Saw `ESC [` (also covers `ESC O` after normalization) — awaiting the final byte, with
    /// these parameter bytes so far.
    Csi,
}

/// Most parameter bytes of an escape sequence the predictor reads; a longer one is not a key it
/// predicts.
const MAX_CSI_PARAMS: usize = 8;

/// The prediction engine.
///
/// Call [`set_local_frame_sent`](Self::set_local_frame_sent) before typed
/// bytes and [`new_user_byte`](Self::new_user_byte) for each;
/// [`set_local_frame_late_acked`](Self::set_local_frame_late_acked) and [`cull`](Self::cull) on a
/// frame; [`overlay`](Self::overlay) to render.
pub struct PredictionEngine {
    pref: DisplayPreference,
    cells: BTreeMap<(u16, u16), PredCell>,
    cursor: Option<PredCursor>,
    prediction_epoch: u64,
    confirmed_epoch: u64,
    local_frame_sent: u64,
    late_acked: u64,
    /// The newest input frame [`hold`](Self::hold) held: nothing is predicted until the server
    /// has reflected it, so no held key shows and nothing is guessed from a model that lacks it.
    held_through: Option<u64>,
    last_size: Option<Size>,
    last_byte: u8,
    /// Where input is in an escape sequence (for arrow keys).
    esc: EscState,
    /// A partial UTF-8 sequence, and the length its lead byte announced (0 when none).
    utf8_buf: Vec<u8>,
    utf8_need: usize,
    /// How the program's PTY takes typed keys, as the newest frame said.
    tty: Option<TtyModes>,
    /// Trust from the last connection to the same session, given once a frame shows no password
    /// prompt.
    carried: bool,
    /// The parameter bytes of the escape sequence being read.
    csi: Vec<u8>,
    /// Where the line being typed began, when known: the first key typed after Enter. Keys that
    /// go to the line's start (`Ctrl-A`, Home, `Ctrl-U`) are predicted only when it is.
    input_start: Option<(u16, u16)>,
    /// Enter was typed and no key since: the next printable key begins a line.
    fresh_line: bool,
}

impl PredictionEngine {
    /// A predictor displaying per `pref`.
    pub fn new(pref: DisplayPreference) -> Self {
        Self {
            pref,
            cells: BTreeMap::new(),
            cursor: None,
            // One epoch ahead of the confirmed one, so the first keystroke stays hidden until the
            // server proves it echoes: a password typed at a silent prompt never shows.
            prediction_epoch: 1,
            confirmed_epoch: 0,
            local_frame_sent: 0,
            late_acked: 0,
            held_through: None,
            last_size: None,
            last_byte: 0,
            esc: EscState::Ground,
            utf8_buf: Vec::new(),
            utf8_need: 0,
            tty: None,
            carried: false,
            csi: Vec::new(),
            input_start: None,
            fresh_line: false,
        }
    }

    /// A fresh engine for a reconnect to the same session: the same preference, and, if typing
    /// was being shown as it was predicted (or trust was carried here and not yet given), trust
    /// from the first key once a frame shows the PTY is not at a password prompt
    /// ([`set_tty`](Self::set_tty)). Taken at the drop and again at the reattach, the trust is
    /// the drop's: nothing between confirms an epoch, so nothing typed then can add to it.
    #[must_use]
    pub fn reattached(&self) -> Self {
        let mut fresh = Self::new(self.pref);
        fresh.carried = self.carried || self.prediction_epoch == self.confirmed_epoch;
        fresh
    }

    /// How the program's PTY takes typed keys, as a frame said.
    ///
    /// At a password prompt (lines read without echo) nothing is predicted and every prediction
    /// goes: a typed secret is never shown, whatever was confirmed before. Otherwise carried trust
    /// is given.
    pub fn set_tty(&mut self, tty: Option<TtyModes>) {
        self.tty = tty;
        if self.password() {
            if !self.cells.is_empty() || self.cursor.is_some() {
                self.reset();
            }
            self.carried = false;
            return;
        }
        if std::mem::take(&mut self.carried) {
            self.confirmed_epoch = self.confirmed_epoch.max(self.prediction_epoch);
        }
    }

    /// Whether the PTY is at a password prompt.
    fn password(&self) -> bool {
        self.tty.is_some_and(TtyModes::password)
    }

    /// Whether the kernel echoes what is typed, so a printable key shows where the cursor is.
    fn kernel_echo(&self) -> bool {
        self.tty.is_some_and(|tty| tty.echo)
    }

    /// What a cell shows, predicted if there is a prediction: what a row shift copies, a wide
    /// glyph's halves included.
    fn guess_at(&self, screen: &dyn ScreenView, row: u16, col: u16) -> Guess {
        if let Some(p) = self.cells.get(&(row, col)) {
            Guess {
                glyph: p.glyph.clone(),
                fg: p.fg,
                bg: p.bg,
                unknown: p.unknown,
                wide: p.wide,
                covered: p.covered,
            }
        } else {
            let (fg, bg) = glyph_style(screen, row, col);
            let cell = screen.cell(row, col);
            Guess {
                glyph: cell_glyph(screen, row, col),
                fg,
                bg,
                unknown: false,
                wide: cell.is_some_and(|c| c.wide),
                covered: cell.is_some_and(|c| c.continuation),
            }
        }
    }

    /// Predict `guess` at `(row, col)`, stamped with the next frame, the current epoch (which hides
    /// it until confirmed) and the glyph it overwrites. One place, so no caller can get the
    /// security-relevant stamps wrong.
    fn place_cell(&mut self, screen: &dyn ScreenView, row: u16, col: u16, guess: Guess) {
        self.cells.insert(
            (row, col),
            PredCell {
                expiration_frame: self.next_frame(),
                tentative_epoch: self.prediction_epoch,
                original_contents: if guess.unknown {
                    None
                } else {
                    Some(cell_glyph(screen, row, col))
                },
                glyph: guess.glyph,
                fg: guess.fg,
                bg: guess.bg,
                unknown: guess.unknown,
                wide: guess.wide,
                covered: guess.covered,
            },
        );
    }

    /// Keep each predicted wide glyph on `row` with its right half: a wide glyph whose right half
    /// is not the next cell's prediction, or a right half whose glyph is not the cell to its left,
    /// was split (by a shift at the edge, or an edit inside a wide glyph) and is unknown.
    fn keep_wide_glyphs_whole(&mut self, row: u16) {
        let known = |cell: Option<&PredCell>, pick: fn(&PredCell) -> bool| {
            cell.is_some_and(|cell| !cell.unknown && pick(cell))
        };
        let split: Vec<u16> = self
            .cells
            .range((row, 0)..=(row, u16::MAX))
            .filter(|(_, cell)| !cell.unknown && (cell.wide || cell.covered))
            .filter(|&(&(_, col), cell)| {
                let whole = if cell.wide {
                    let right = col.checked_add(1).map(|right| (row, right));
                    known(right.and_then(|at| self.cells.get(&at)), |c| c.covered)
                } else {
                    let left = col.checked_sub(1).map(|left| (row, left));
                    known(left.and_then(|at| self.cells.get(&at)), |c| c.wide)
                };
                !whole
            })
            .map(|(&(_, col), _)| col)
            .collect();
        for col in split {
            if let Some(cell) = self.cells.get_mut(&(row, col)) {
                cell.glyph.clear();
                cell.unknown = true;
                cell.wide = false;
                cell.covered = false;
                cell.original_contents = None;
            }
        }
    }

    /// The newest epoch the server confirmed echoes. Test-only.
    #[cfg(test)]
    pub fn confirmed_epoch(&self) -> u64 {
        self.confirmed_epoch
    }
    /// Whether trust carried from a lost connection waits to be given. Test-only.
    #[cfg(test)]
    pub(crate) const fn carries_trust(&self) -> bool {
        self.carried
    }
    /// Confirm the newest epoch, as an echo would. Test-only.
    #[cfg(test)]
    pub(crate) fn confirm_for_tests(&mut self) {
        self.confirmed_epoch = self.prediction_epoch;
    }
    /// The newest local input frame number sent so far (predictions expire at this + 1).
    pub fn set_local_frame_sent(&mut self, n: u64) {
        self.local_frame_sent = n;
    }
    /// The server's echo-ack: the newest input frame reflected on screen.
    pub fn set_local_frame_late_acked(&mut self, n: u64) {
        self.late_acked = n;
    }

    /// The frame a prediction made now expires at: the next input frame. Saturating, so it never
    /// wraps to an expired 0.
    fn next_frame(&self) -> u64 {
        self.local_frame_sent.saturating_add(1)
    }

    fn become_tentative(&mut self) {
        // Saturating: wrapping below `confirmed_epoch` would show unconfirmed predictions.
        self.prediction_epoch = self.prediction_epoch.saturating_add(1);
    }

    fn tentative(&self, epoch: u64) -> bool {
        epoch > self.confirmed_epoch
    }

    /// Ensure a cursor prediction exists in the current epoch, seeded from the real cursor, and
    /// return it.
    fn init_cursor(&mut self, screen: &dyn ScreenView) -> &mut PredCursor {
        let epoch = self.prediction_epoch;
        let expiration_frame = self.next_frame();
        let (row, col) = screen.cursor_position();
        let cursor = self.cursor.get_or_insert(PredCursor {
            expiration_frame,
            tentative_epoch: epoch,
            row,
            col,
        });
        if cursor.tentative_epoch != epoch {
            // A new epoch keeps the predicted position but restarts confirmation.
            *cursor = PredCursor {
                expiration_frame,
                tentative_epoch: epoch,
                row: cursor.row,
                col: cursor.col,
            };
        }
        cursor
    }

    fn newline_cr(&mut self, screen: &dyn ScreenView) {
        let rows = screen.size().rows;
        self.init_cursor(screen);
        if let Some(c) = self.cursor.as_mut() {
            c.col = 0;
            if let Some(next) = c.row.checked_add(1).filter(|&next| next < rows) {
                c.row = next;
            }
            // On the last row we do NOT predict a scroll (mosh deliberately avoids it).
        }
    }

    /// Predict the cursor moving right (`dir > 0`) or left within the row, in the current epoch.
    fn predict_arrow(&mut self, screen: &dyn ScreenView, dir: i32) {
        self.init_cursor(screen);
        let exp = self.next_frame();
        let cols = screen.size().cols;
        if let Some(c) = self.cursor.as_mut() {
            // Right stops before the last column, left at column 0.
            let moved = match dir.cmp(&0) {
                std::cmp::Ordering::Greater => c.col.checked_add(1).filter(|&next| next < cols),
                std::cmp::Ordering::Less => c.col.checked_sub(1),
                std::cmp::Ordering::Equal => None,
            };
            if let Some(col) = moved {
                c.col = col;
                c.expiration_frame = exp;
            }
        }
    }

    /// Predict the grapheme `g` at the cursor and advance it by `g`'s width. A zero-width one, or
    /// one reaching the right edge (where the terminal may wrap), opens a new epoch instead. It
    /// overwrites, with no insert-mode shift; a wide one covers the next cell too.
    fn predict_wide(&mut self, g: &str, screen: &dyn ScreenView) {
        let w = u16::try_from(g.width()).unwrap_or(u16::MAX);
        if w == 0 {
            self.become_tentative(); // combining / zero-width: can't place safely
            return;
        }
        let cols = screen.size().cols;
        let (row, col) = {
            let c = self.init_cursor(screen);
            (c.row, c.col)
        };
        // It must end before the last column, where the terminal may wrap.
        let Some(next_col) = col.checked_add(w).filter(|&next| next < cols) else {
            self.become_tentative();
            self.init_cursor(screen);
            return;
        };
        let exp = self.next_frame();
        let (fg, bg) = glyph_style(screen, row, col);
        let wide = w == 2;
        self.place_cell(screen, row, col, Guess::glyph(g.to_string(), wide, fg, bg));
        if let Some(right) = col.checked_add(1).filter(|_| wide) {
            self.place_cell(screen, row, right, Guess::covered(fg, bg));
        }
        self.keep_wide_glyphs_whole(row);
        if let Some(c) = self.cursor.as_mut() {
            c.expiration_frame = exp;
            c.col = next_col;
        }
    }

    /// A key not modelled: a new epoch, nothing predicted, and where the line began is no longer
    /// known (the key may have recalled another line, or moved the cursor anywhere).
    fn unmodelled(&mut self) {
        self.become_tentative();
        self.input_start = None;
        self.fresh_line = false;
    }

    /// Whether line editing keys may be predicted: a line editor reads keys (no kernel echo, which
    /// edits a line its own way).
    fn editing(&self) -> bool {
        !self.kernel_echo()
    }

    /// The predicted cursor's row and column, else the screen's.
    fn cursor_at(&self, screen: &dyn ScreenView) -> (u16, u16) {
        self.cursor
            .as_ref()
            .map_or_else(|| screen.cursor_position(), |c| (c.row, c.col))
    }

    /// The glyph `(row, col)` shows, predicted or not, or `None` if it is unknown or half of a
    /// wide glyph, where word boundaries cannot be read.
    fn glyph_at(&self, screen: &dyn ScreenView, row: u16, col: u16) -> Option<String> {
        let guess = self.guess_at(screen, row, col);
        (!guess.unknown && !guess.wide && !guess.covered).then_some(guess.glyph)
    }

    /// Whether the cell at `(row, col)` holds a character `word` accepts. Blank is no word.
    fn in_word(
        &self,
        screen: &dyn ScreenView,
        row: u16,
        col: u16,
        word: fn(char) -> bool,
    ) -> Option<bool> {
        let glyph = self.glyph_at(screen, row, col)?;
        Some(glyph.chars().next().is_some_and(word))
    }

    /// Delete the `n` cells before the cursor as a line editor does: the cursor steps back `n`,
    /// the rest of the row shifts left, and the last cells take what was off-screen (unknown).
    /// Nothing is predicted if a wide glyph is in the way.
    fn delete_before(&mut self, screen: &dyn ScreenView, n: u16) {
        let cols = screen.size().cols;
        let (row, col) = self.cursor_at(screen);
        let Some(to) = col.checked_sub(n).filter(|_| n > 0) else {
            return;
        };
        self.init_cursor(screen);
        if (to..cols).any(|c| {
            let g = self.guess_at(screen, row, c);
            g.wide || g.covered
        }) {
            self.unmodelled();
            return;
        }
        for i in to..cols {
            let from = i
                .checked_add(n)
                .filter(|&from| from < cols.saturating_sub(1));
            let guess = match from {
                Some(from) => self.guess_at(screen, row, from),
                None => Guess::unknown(Color::Default, Color::Default),
            };
            let guess = if guess.unknown {
                Guess::unknown(guess.fg, guess.bg)
            } else {
                guess
            };
            self.place_cell(screen, row, i, guess);
        }
        let exp = self.next_frame();
        if let Some(c) = self.cursor.as_mut() {
            c.col = to;
            c.expiration_frame = exp;
        }
    }

    /// `Ctrl-W` (`word` is not whitespace) or `Alt-Backspace` (`word` is alphanumeric): delete
    /// back over what is not a word, then over the word. Predicted only when the word is bounded
    /// on its left by a cell that is not one, after where the line began if that is known, so a
    /// prompt is never taken for the line.
    fn predict_kill_word(&mut self, screen: &dyn ScreenView, word: fn(char) -> bool) {
        if !self.editing() {
            return self.unmodelled();
        }
        let (row, col) = self.cursor_at(screen);
        let floor = self
            .input_start
            .filter(|(r, _)| *r == row)
            .map_or(0, |(_, c)| c);
        let mut at = col;
        let mut seen_word = false;
        loop {
            let Some(prev) = at.checked_sub(1).filter(|&p| p >= floor) else {
                // Reached the line's start (or the row's): sure only if where the line began is
                // known, and something was deleted.
                if self.input_start.is_some() && at < col {
                    break;
                }
                return self.unmodelled();
            };
            match self.in_word(screen, row, prev, word) {
                None => return self.unmodelled(),
                Some(true) => seen_word = true,
                Some(false) if seen_word => break,
                Some(false) => {}
            }
            at = prev;
        }
        let n = col.saturating_sub(at);
        if n == 0 {
            return self.unmodelled();
        }
        self.delete_before(screen, n);
    }

    /// `Ctrl-U`: delete from where the line began to the cursor, if that is known.
    fn predict_kill_line(&mut self, screen: &dyn ScreenView) {
        let (row, col) = self.cursor_at(screen);
        match self.input_start.filter(|(r, c)| *r == row && *c <= col) {
            Some((_, start)) if self.editing() => {
                self.delete_before(screen, col.saturating_sub(start));
            }
            _ => self.unmodelled(),
        }
    }

    /// Move the predicted cursor to `col` on its row.
    fn move_cursor_to(&mut self, screen: &dyn ScreenView, col: u16) {
        self.init_cursor(screen);
        let exp = self.next_frame();
        if let Some(c) = self.cursor.as_mut() {
            c.col = col;
            c.expiration_frame = exp;
        }
    }

    /// `Ctrl-A`, Home: the cursor to where the line began, if that is known.
    fn predict_line_start(&mut self, screen: &dyn ScreenView) {
        let (row, _) = self.cursor_at(screen);
        match self.input_start.filter(|(r, _)| *r == row) {
            Some((_, start)) if self.editing() => self.move_cursor_to(screen, start),
            _ => self.unmodelled(),
        }
    }

    /// `Ctrl-E`, End: the cursor past the last character of its row, if the line ends on it (the
    /// row is not soft-wrapped into the next) and that is at or after the cursor.
    fn predict_line_end(&mut self, screen: &dyn ScreenView) {
        let cols = screen.size().cols;
        let (row, col) = self.cursor_at(screen);
        let mut end = 0_u16;
        for c in 0..cols {
            // Typing and deleting leave the last two columns unknown (what an edit pushed off or
            // pulled in): blank unless the line nearly fills the row.
            let edge = c >= cols.saturating_sub(2);
            match self.glyph_at(screen, row, c) {
                None if edge => {}
                None => return self.unmodelled(),
                Some(g) if !is_blank(&g) => end = c.saturating_add(1),
                Some(_) => {}
            }
        }
        if !self.editing() || end < col || end >= cols {
            return self.unmodelled();
        }
        self.move_cursor_to(screen, end);
    }

    /// `Alt-B` (back) or `Alt-F` (`forward`): the cursor over what is not alphanumeric, then over
    /// a word, as readline moves; predicted only when it stops inside the row, and inside the line
    /// if where it began is known.
    fn predict_word_motion(&mut self, screen: &dyn ScreenView, forward: bool) {
        if !self.editing() {
            return self.unmodelled();
        }
        let cols = screen.size().cols;
        let (row, col) = self.cursor_at(screen);
        let floor = self
            .input_start
            .filter(|(r, _)| *r == row)
            .map_or(0, |(_, c)| c);
        let mut at = col;
        let mut seen_word = false;
        loop {
            // The cell to step over: the one before, back; the one at the cursor, forward.
            let next = if forward {
                Some(at).filter(|&a| a < cols.saturating_sub(1))
            } else {
                at.checked_sub(1).filter(|&p| p >= floor)
            };
            let Some(cell) = next else {
                if !forward && self.input_start.is_some() && seen_word {
                    break;
                }
                return self.unmodelled();
            };
            match self.in_word(screen, row, cell, char::is_alphanumeric) {
                None => return self.unmodelled(),
                Some(true) => seen_word = true,
                Some(false) if seen_word => break,
                Some(false)
                    if forward
                        && self
                            .glyph_at(screen, row, cell)
                            .is_some_and(|g| is_blank(&g)) =>
                {
                    // Past the line's end: readline stops at it; where that is, is not sure.
                    return self.unmodelled();
                }
                Some(false) => {}
            }
            at = if forward {
                cell.saturating_add(1)
            } else {
                cell
            };
        }
        if at == col {
            return self.unmodelled();
        }
        self.move_cursor_to(screen, at);
    }

    /// Predict what typed key `press` does to `screen`. The key is read in its one legacy form,
    /// the bytes a legacy terminal sends for it in normal cursor mode, whatever the user's
    /// terminal sent: `Alt-B` is `ESC b` from a kitty-protocol terminal too. A key legacy bytes
    /// cannot tell from another (Shift-Enter) is predicted as that other.
    pub fn new_user_key(&mut self, press: KeyPress, screen: &dyn ScreenView) {
        let mut bytes = Vec::with_capacity(8);
        key_bytes(press.into(), KeyMode::legacy(false), &mut bytes);
        for byte in bytes {
            self.new_user_byte(byte, screen);
        }
    }

    /// Predict nothing for what is typed now, nor after, until the server has reflected it: for a
    /// key whose echo is in doubt. The client may not yet know the PTY's modes as they are now (a
    /// program that printed a prompt may turn echo off a moment after), and a key typed at a
    /// password prompt must never be shown. Predictions already made stand.
    pub fn hold(&mut self) {
        self.held_through = Some(self.next_frame());
        self.become_tentative();
    }

    /// Whether a held key is not yet reflected on the screen.
    fn holding(&mut self) -> bool {
        match self.held_through {
            Some(held) if self.late_acked < held => true,
            Some(_) => {
                self.held_through = None;
                false
            }
            None => false,
        }
    }

    /// Input the predictor does not model reached the program (a mouse event, a focus change, a
    /// paste): what it shows next is unknown.
    pub fn new_user_other(&mut self, screen: &dyn ScreenView) {
        if self.pref == DisplayPreference::Never {
            return;
        }
        if self.password() {
            self.become_tentative();
            return;
        }
        self.cull(screen);
        self.unmodelled();
    }

    /// Predict what typed `byte` does to `screen`, after culling the existing predictions.
    pub fn new_user_byte(&mut self, byte: u8, screen: &dyn ScreenView) {
        if self.pref == DisplayPreference::Never {
            return;
        }
        if self.password() {
            // Nothing typed at a password prompt is predicted, nor shown.
            self.become_tentative();
            return;
        }
        self.cull(screen);
        if self.holding() {
            return;
        }

        let mut byte = byte;
        if self.last_byte == 0x1b && byte == b'O' {
            byte = b'['; // application-cursor-mode arrow normalization
        }
        self.last_byte = byte;

        let Size { rows, cols } = screen.size();
        if rows == 0 || cols == 0 {
            return;
        }

        // Before escapes: a continuation byte is never an escape's final byte.
        if self.utf8_need > 0 {
            if (0x80..=0xbf).contains(&byte) {
                self.utf8_buf.push(byte);
                if self.utf8_buf.len() >= self.utf8_need {
                    let decoded = std::str::from_utf8(&self.utf8_buf).ok().map(str::to_string);
                    self.utf8_buf.clear();
                    self.utf8_need = 0;
                    match decoded {
                        Some(s) => self.predict_wide(&s, screen),
                        None => self.become_tentative(),
                    }
                }
                return;
            }
            // Malformed: drop the partial grapheme and take this byte afresh.
            self.utf8_buf.clear();
            self.utf8_need = 0;
            self.become_tentative();
        }

        // Swallow escape sequences, predicting the keys modelled (`ESC O x` became `ESC [ x`).
        match self.esc {
            EscState::Esc => {
                self.esc = EscState::Ground;
                match byte {
                    b'[' => {
                        self.esc = EscState::Csi;
                        self.csi.clear();
                    }
                    b'b' => self.predict_word_motion(screen, false),
                    b'f' => self.predict_word_motion(screen, true),
                    0x7f | 0x08 => self.predict_kill_word(screen, char::is_alphanumeric),
                    _ => self.unmodelled(), // an escape we don't model -> wait for the server
                }
                return;
            }
            EscState::Csi => {
                if (0x20..=0x3f).contains(&byte) && self.csi.len() < MAX_CSI_PARAMS {
                    self.csi.push(byte);
                    return;
                }
                self.esc = EscState::Ground;
                let params = std::mem::take(&mut self.csi);
                match (params.as_slice(), byte) {
                    (b"", b'C') => self.predict_arrow(screen, 1),  // right
                    (b"", b'D') => self.predict_arrow(screen, -1), // left
                    (b"" | b"1", b'H') | (b"1" | b"7", b'~') => self.predict_line_start(screen),
                    (b"" | b"1", b'F') | (b"4" | b"8", b'~') => self.predict_line_end(screen),
                    // Anything else is not predicted.
                    _ => self.unmodelled(),
                }
                return;
            }
            EscState::Ground => {}
        }
        if byte == 0x1b {
            self.esc = EscState::Esc;
            return;
        }

        // A UTF-8 lead byte (>= 0x80) starts a 2-4 byte grapheme; buffer it and await the rest.
        if byte >= 0x80 {
            self.utf8_need = match byte {
                0xc0..=0xdf => 2,
                0xe0..=0xef => 3,
                0xf0..=0xf7 => 4,
                _ => 0, // stray continuation or invalid lead -> nothing concrete to predict
            };
            if self.utf8_need >= 2 {
                self.utf8_buf.clear();
                self.utf8_buf.push(byte);
            } else {
                self.become_tentative();
            }
            return;
        }

        match byte {
            0x20..=0x7e => {
                if self.kernel_echo() {
                    // The kernel echoes it: no need to wait for the program to prove it does.
                    self.confirmed_epoch = self.confirmed_epoch.max(self.prediction_epoch);
                }
                if std::mem::take(&mut self.fresh_line) {
                    let c = self.init_cursor(screen);
                    self.input_start = Some((c.row, c.col));
                }
                let col = self.init_cursor(screen).col;
                if col >= cols.saturating_sub(1) {
                    // Last column is ambiguous (wrap vs. overwrite); hide until confirmed.
                    self.become_tentative();
                }
                let (row, col) = {
                    let c = self.init_cursor(screen);
                    (c.row, c.col)
                };
                // Insert mode, as a line editor renders it: shift the tail right, from the right end
                // so each cell reads its left neighbour's content before it moves. A wide glyph
                // moves with its right half; one split at the edge is unknown.
                for (left, i) in (col..cols).zip((col..cols).skip(1)).rev() {
                    let guess = self.guess_at(screen, row, left);
                    // The rightmost cell takes content pushed off-screen -> unknown.
                    let guess = if i.checked_add(1) == Some(cols) || guess.unknown {
                        Guess::unknown(guess.fg, guess.bg)
                    } else {
                        guess
                    };
                    self.place_cell(screen, row, i, guess);
                }
                let (fg, bg) = glyph_style(screen, row, col);
                let typed = Guess::glyph((byte as char).to_string(), false, fg, bg);
                self.place_cell(screen, row, col, typed);
                self.keep_wide_glyphs_whole(row);
                let exp = self.next_frame();
                if let Some(c) = self.cursor.as_mut() {
                    c.expiration_frame = exp;
                    // Advance unless on the last column.
                    if let Some(next) = c.col.checked_add(1).filter(|&next| next < cols) {
                        c.col = next;
                    } else {
                        self.become_tentative();
                        self.newline_cr(screen);
                    }
                }
            }
            0x7f | 0x08 => {
                // Backspace over a wide glyph deletes both its halves, which is not modelled: a new
                // epoch, nothing predicted.
                let (row, col) = self
                    .cursor
                    .as_ref()
                    .map_or_else(|| screen.cursor_position(), |c| (c.row, c.col));
                if let Some(prev) = col.checked_sub(1) {
                    let deleted = self.guess_at(screen, row, prev);
                    if deleted.wide || deleted.covered {
                        self.become_tentative();
                        return;
                    }
                }
                // Backspace: step the cursor back one column.
                let exp = self.next_frame();
                let (row, col, do_pred) = {
                    let c = self.init_cursor(screen);
                    if let Some(prev) = c.col.checked_sub(1) {
                        c.col = prev;
                        c.expiration_frame = exp;
                        (c.row, c.col, true)
                    } else {
                        (c.row, c.col, false)
                    }
                };
                if do_pred {
                    // Shift the tail left, from the left so each cell reads its neighbour before it
                    // moves. The last two columns take what was off-screen, so they are unknown,
                    // as in mosh: a wide glyph could straddle the second-to-last.
                    for i in col..cols {
                        // `i < cols - 2` is mosh's `i + 2 < width` without overflow.
                        let right = i.checked_add(1).filter(|_| i < cols.saturating_sub(2));
                        let guess = match right {
                            Some(right) => self.guess_at(screen, row, right),
                            None => Guess::unknown(Color::Default, Color::Default),
                        };
                        let guess = if guess.unknown {
                            Guess::unknown(guess.fg, guess.bg)
                        } else {
                            guess
                        };
                        self.place_cell(screen, row, i, guess);
                    }
                    self.keep_wide_glyphs_whole(row);
                }
            }
            0x0d | 0x0a => {
                // A scroll cannot be predicted cleanly: a new epoch, and the cursor moves.
                self.become_tentative();
                self.newline_cr(screen);
                self.input_start = None;
                self.fresh_line = true;
            }
            0x17 => self.predict_kill_word(screen, |c| !c.is_whitespace()), // Ctrl-W
            0x15 => self.predict_kill_line(screen),                         // Ctrl-U
            0x01 => self.predict_line_start(screen),                        // Ctrl-A
            0x05 => self.predict_line_end(screen),                          // Ctrl-E
            _ => {
                // Other controls: a new epoch, nothing predicted.
                self.unmodelled();
            }
        }
    }

    pub fn cull(&mut self, screen: &dyn ScreenView) {
        if self.pref == DisplayPreference::Never {
            return;
        }
        let size = screen.size();
        // Reset predictions on a genuine resize, but not on the very first cull.
        if let Some(prev) = self.last_size {
            if prev != size {
                self.last_size = Some(size);
                self.reset();
                return;
            }
        }
        self.last_size = Some(size);
        let Size { rows, cols } = size;

        let late = self.late_acked;
        let confirmed = self.confirmed_epoch;

        let mut to_remove: Vec<(u16, u16)> = Vec::new();
        let mut kill_epochs: BTreeSet<u64> = BTreeSet::new();
        let mut kill_all = false;
        let mut max_confirm = confirmed;
        // As mosh does, a confirmed cell's actual colours recolour the pending predictions right of
        // it, so they don't show a guessed colour until their own frame: `(row, from_col, fg, bg)`,
        // applied after this pass.
        let mut rendition_runs: Vec<(u16, u16, Color, Color)> = Vec::new();

        for (&(row, col), cell) in &self.cells {
            let v = cell_validity(cell, screen, row, col, rows, cols, late);
            match v {
                Validity::Pending => {}
                Validity::Correct => {
                    if cell.tentative_epoch > max_confirm {
                        max_confirm = cell.tentative_epoch;
                    }
                    let (afg, abg) = screen
                        .cell(row, col)
                        .map_or((Color::Default, Color::Default), |c| (c.fg, c.bg));
                    rendition_runs.push((row, col, afg, abg));
                    to_remove.push((row, col));
                }
                Validity::CorrectNoCredit => {
                    to_remove.push((row, col));
                }
                Validity::IncorrectOrExpired => {
                    if self.tentative(cell.tentative_epoch) {
                        kill_epochs.insert(cell.tentative_epoch);
                        to_remove.push((row, col));
                    } else {
                        kill_all = true;
                    }
                }
            }
        }

        if kill_all {
            self.reset();
            return;
        }

        self.confirmed_epoch = max_confirm;
        for k in &to_remove {
            self.cells.remove(k);
        }
        // In order, so the rightmost confirmed cell's colours win, as in mosh.
        for &(row, from_col, fg, bg) in &rendition_runs {
            for (_, cell) in self.cells.range_mut((row, from_col)..=(row, u16::MAX)) {
                cell.fg = fg;
                cell.bg = bg;
            }
        }
        if !kill_epochs.is_empty() {
            self.cells
                .retain(|_, c| !kill_epochs.contains(&c.tentative_epoch));
            self.become_tentative();
            // As mosh's kill_epoch: a new cursor at the real position, in the new (hidden) epoch,
            // so the killed epoch's cursor is not drawn.
            let (crow, ccol) = screen.cursor_position();
            self.cursor = Some(PredCursor {
                expiration_frame: self.next_frame(),
                tentative_epoch: self.prediction_epoch,
                row: crow,
                col: ccol,
            });
        }

        if let Some(c) = &self.cursor {
            let cv = cursor_validity(c, screen, late);
            match cv {
                Validity::IncorrectOrExpired => {
                    self.reset();
                }
                Validity::Pending => {}
                Validity::Correct | Validity::CorrectNoCredit => {
                    self.cursor = None; // resolved
                }
            }
        }
    }

    /// What to draw now: the predictions in confirmed epochs, unless predictions are off.
    pub fn overlay(&self) -> Overlay<'_> {
        if self.pref == DisplayPreference::Never || self.password() {
            return Overlay::empty();
        }
        let mut ov = Overlay::empty();
        for (&(row, col), cell) in &self.cells {
            if self.tentative(cell.tentative_epoch) {
                continue; // hidden until its epoch is confirmed
            }
            if cell.unknown {
                // Show the real cell, not a guess.
                continue;
            }
            ov.cells.insert(
                (row, col),
                PredictedCell {
                    glyph: &cell.glyph,
                    fg: cell.fg,
                    bg: cell.bg,
                    covered: cell.covered,
                },
            );
        }
        if let Some(c) = &self.cursor {
            if !self.tentative(c.tentative_epoch) {
                ov.cursor = Some((c.row, c.col));
            }
        }
        ov
    }

    /// Drop all predictions and open a fresh epoch (after a mispredict or a resize).
    pub fn reset(&mut self) {
        self.cells.clear();
        self.cursor = None;
        self.reset_decoder();
        self.become_tentative();
    }

    /// Forget a partial escape sequence or grapheme, which would misread the next byte after a
    /// resize.
    fn reset_decoder(&mut self) {
        self.esc = EscState::Ground;
        self.csi.clear();
        self.utf8_buf.clear();
        self.utf8_need = 0;
        self.last_byte = 0;
    }
}

fn cell_glyph(screen: &dyn ScreenView, row: u16, col: u16) -> String {
    screen
        .cell(row, col)
        .filter(|c| !c.contents.is_empty())
        .map(|c| c.contents.to_string())
        .unwrap_or_default()
}

fn glyph_style(screen: &dyn ScreenView, row: u16, col: u16) -> (Color, Color) {
    // The colours of the neighbour to the left if it has content, else the defaults.
    if let Some(left) = col.checked_sub(1) {
        if let Some(c) = screen.cell(row, left) {
            if !c.contents.is_empty() {
                return (c.fg, c.bg);
            }
        }
    }
    (Color::Default, Color::Default)
}

fn is_blank(s: &str) -> bool {
    s.is_empty() || s == " "
}

fn cell_validity(
    cell: &PredCell,
    screen: &dyn ScreenView,
    row: u16,
    col: u16,
    rows: u16,
    cols: u16,
    late_acked: u64,
) -> Validity {
    if row >= rows || col >= cols {
        return Validity::IncorrectOrExpired;
    }
    if late_acked < cell.expiration_frame {
        return Validity::Pending;
    }
    if cell.unknown {
        // We never predicted a concrete glyph here, so it can never *confirm* an epoch.
        return Validity::CorrectNoCredit;
    }
    if cell.covered {
        // A wide glyph's right half says nothing of its own: right when the server shows one here,
        // never credit (its glyph, to the left, is graded).
        return if screen.cell(row, col).is_some_and(|c| c.continuation) {
            Validity::CorrectNoCredit
        } else {
            Validity::IncorrectOrExpired
        };
    }
    if is_blank(&cell.glyph) {
        return Validity::CorrectNoCredit; // too easy to falsely match
    }
    let actual = cell_glyph(screen, row, col);
    if actual == cell.glyph {
        if cell.original_contents.as_deref() == Some(actual.as_str()) {
            Validity::CorrectNoCredit // it already looked like this earlier; no credit
        } else {
            Validity::Correct
        }
    } else {
        Validity::IncorrectOrExpired
    }
}

fn cursor_validity(cur: &PredCursor, screen: &dyn ScreenView, late_acked: u64) -> Validity {
    let Size { rows, cols } = screen.size();
    if cur.row >= rows || cur.col >= cols {
        return Validity::IncorrectOrExpired;
    }
    if late_acked >= cur.expiration_frame {
        let (arow, acol) = screen.cursor_position();
        if arow == cur.row && acol == cur.col {
            Validity::Correct
        } else {
            Validity::IncorrectOrExpired
        }
    } else {
        Validity::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use fux_vt::keys::decode::{Decoder, Input};
    use fux_vt::Screen;

    impl ScreenView for Screen {
        fn size(&self) -> Size {
            let (rows, cols) = Self::size(self);
            Size { rows, cols }
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

    /// Type `bytes` into `e` over `screen`, read as the keys and other input they decode to.
    fn type_bytes(e: &mut PredictionEngine, screen: &dyn ScreenView, bytes: &[u8]) {
        let mut decoder = Decoder::default();
        let mut input = Vec::new();
        decoder.bytes(bytes, &mut input);
        decoder.timeout(&mut input);
        for input in input {
            match input {
                Input::Key(key) => e.new_user_key(key.press, screen),
                Input::Paste(_)
                | Input::PasteTooLong
                | Input::FocusIn
                | Input::FocusOut
                | Input::Mouse(_)
                | Input::Reply(_) => e.new_user_other(screen),
            }
        }
    }

    fn screen_of(bytes: &[u8]) -> Screen {
        let mut p = fux_vt::Parser::new(24, 80, 0).expect("24x80 parser");
        p.process(bytes).expect("process");
        p.screen().clone()
    }

    /// A screen that is NOT an emulator: a plain char grid with a cursor.
    struct FakeView {
        rows: Vec<Vec<char>>,
        cursor: (u16, u16),
    }

    impl ScreenView for FakeView {
        fn size(&self) -> Size {
            Size::new(
                u16::try_from(self.rows.len()).expect("rows fit u16"),
                u16::try_from(self.rows[0].len()).expect("columns fit u16"),
            )
        }
        fn cursor_position(&self) -> (u16, u16) {
            self.cursor
        }
        fn cell(&self, row: u16, col: u16) -> Option<CellView<'_>> {
            // Leak-free static strs for the tiny alphabet the test uses.
            let ch = *self.rows.get(row as usize)?.get(col as usize)?;
            let contents: &'static str = match ch {
                ' ' => "",
                'x' => "x",
                'y' => "y",
                _ => "?",
            };
            Some(CellView {
                contents,
                fg: Color::Default,
                bg: Color::Default,
                wide: false,
                continuation: false,
            })
        }
    }

    #[test]
    fn predictor_runs_over_a_plain_screen_view() {
        // The exact flow of `confirm_first_keystroke`, but over a 5×10 fake grid that is
        // not an emulator: the first keystroke is hidden, the server's echo confirms the epoch, and the
        // next keystroke is visible at the right column. Proves the engine needs no emulator.
        let blank = FakeView {
            rows: vec![vec![' '; 10]; 5],
            cursor: (0, 0),
        };
        let mut e = PredictionEngine::new(DisplayPreference::Always);
        e.set_local_frame_sent(0);
        type_bytes(&mut e, &blank, b"x");
        assert!(e.overlay().is_empty(), "hidden until confirmed");
        let mut echoed = FakeView {
            rows: vec![vec![' '; 10]; 5],
            cursor: (0, 1),
        };
        echoed.rows[0][0] = 'x';
        e.set_local_frame_late_acked(1);
        e.cull(&echoed);
        assert_eq!(e.confirmed_epoch(), 1, "the echoed 'x' confirms the epoch");
        e.set_local_frame_sent(1);
        type_bytes(&mut e, &echoed, b"y");
        let ov = e.overlay();
        assert_eq!(
            ov.cell(0, 1).map(|c| c.glyph),
            Some("y"),
            "typing after confirmation is visible over the fake view"
        );
    }

    #[test]
    fn malformed_utf8_midgrapheme_resets_without_panicking() {
        // A lead byte announcing a multi-byte grapheme followed by a NON-continuation byte must
        // reset the UTF-8 accumulator (no concrete prediction, fall back to the server's echo) and
        // must never panic or mis-draw the bytes as literal glyphs.
        let mut pe = PredictionEngine::new(DisplayPreference::Always);
        pe.set_local_frame_sent(0);
        let screen = screen_of(b"");
        pe.new_user_byte(0xE4, &screen); // lead byte of a 3-byte sequence
        pe.new_user_byte(b'A', &screen); // not a continuation -> reset
        assert!(
            pe.utf8_buf.is_empty(),
            "the UTF-8 accumulator must reset after a malformed sequence"
        );
        let _ = pe.overlay();
    }

    #[test]
    fn reset_clears_partial_decoder_state() {
        // A resize calls reset() mid-stream. If it lands right after a UTF-8 lead byte (or inside an
        // escape sequence), those partial bytes must NOT survive reset() to mis-decode the next typed
        // byte: reset() clears the decoder (esc / utf8_buf / utf8_need / last_byte) along with the
        // prediction cells and cursor.
        let mut pe = PredictionEngine::new(DisplayPreference::Always);
        pe.set_local_frame_sent(0);
        let screen = screen_of(b"");
        // Mid-grapheme: feed the lead byte of a 2-byte sequence, leaving a continuation outstanding.
        pe.new_user_byte(0xC3, &screen);
        assert_eq!(
            pe.utf8_buf,
            vec![0xC3],
            "the lead byte is buffered awaiting its continuation"
        );
        assert_eq!(pe.utf8_need, 2);

        pe.reset(); // a resize lands here

        assert!(
            pe.utf8_buf.is_empty(),
            "reset must drop the partial UTF-8 buffer"
        );
        assert_eq!(pe.utf8_need, 0, "reset must clear the awaited-byte count");
        assert_eq!(
            pe.last_byte, 0,
            "reset must clear the arrow-decode last-byte state"
        );
        assert!(
            matches!(pe.esc, EscState::Ground),
            "reset must return the escape state machine to Ground"
        );

        // The next byte now decodes cleanly as ASCII, not as a stray continuation of the dropped
        // grapheme.
        pe.new_user_byte(b'A', &screen);
        assert!(
            pe.utf8_buf.is_empty(),
            "the post-reset byte decodes cleanly"
        );
        let _ = pe.overlay();
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

        /// Feeding ARBITRARY byte streams (escape bytes, partial UTF-8, arrows interleaved) to the
        /// byte-at-a-time predictor against a fixed screen must never panic and must keep the UTF-8
        /// accumulator bounded (<= 4 bytes). The predictor is a stateful decoder over local input —
        /// exactly the shape that fuzzes well — and a 1.4k-LOC module with no prior property coverage.
        #[test]
        fn prop_new_user_byte_is_panic_free_and_utf8_bounded(
            bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..256),
        ) {
            let fake = FakeView { rows: vec![vec![' '; 80]; 24], cursor: (0, 0) };
            let mut pf = PredictionEngine::new(DisplayPreference::Always);
            pf.set_local_frame_sent(0);
            for &b in &bytes {
                pf.new_user_byte(b, &fake);
                proptest::prop_assert!(pf.utf8_buf.len() <= 4, "utf8 accumulator over the fake view");
            }
            let mut pe = PredictionEngine::new(DisplayPreference::Always);
            pe.set_local_frame_sent(0);
            let screen = screen_of(b"ready prompt $ ");
            let mut now = 0u64;
            for b in &bytes {
                pe.new_user_byte(*b, &screen); // must not panic on any byte sequence
                now = now.saturating_add(1);
                proptest::prop_assert!(
                    pe.utf8_buf.len() <= 4,
                    "UTF-8 accumulator grew past 4 bytes: {}",
                    pe.utf8_buf.len()
                );
            }
            let _ = pe.overlay(); // must not panic on the accumulated prediction set
        }

        /// Whatever is typed over a screen of wide glyphs, a wide glyph the overlay shows has the
        /// next cell covered, and a covered cell follows one: the renderer draws them whole.
        #[test]
        fn predicted_wide_glyphs_are_shown_whole(
            bytes in proptest::collection::vec(
                proptest::sample::select(
                    [&b"a"[..], "日".as_bytes(), "\u{1f980}".as_bytes(), b"\x7f", b"\x1b[D", b"\x1b[C", b"\r"]
                        .to_vec(),
                ),
                0..40,
            ),
            start in 0u16..12,
        ) {
            let screen = sized_screen_of(3, 12, format!("本x日 ab本\x1b[1;{}H", start.saturating_add(1)).as_bytes());
            let mut e = PredictionEngine::new(DisplayPreference::Always);
            // Everything shown: the check is on what the overlay holds, not on when it confirms.
            e.confirmed_epoch = u64::MAX;
            e.set_local_frame_sent(0);
            for key in bytes {
                type_bytes(&mut e, &screen, key);
                let ov = e.overlay();
                for ((row, col), cell) in ov.cells() {
                    let left = col.checked_sub(1).and_then(|left| ov.cell(row, left));
                    let right = col.checked_add(1).and_then(|right| ov.cell(row, right));
                    if cell.covered {
                        proptest::prop_assert!(
                            left.is_some_and(|l| !l.covered && l.glyph.width() == 2),
                            "a covered cell at {col} follows no wide glyph"
                        );
                    } else if cell.glyph.width() == 2 {
                        proptest::prop_assert!(
                            right.is_some_and(|r| r.covered),
                            "a wide glyph at {col} covers nothing"
                        );
                    }
                }
            }
        }
    }

    /// Drive a confirmation round: type `first` (hidden), have the server echo it on `echoed`
    /// and ack frame 1, cull (advancing `confirmed_epoch`). Returns the engine ready for
    /// subsequent typing to be *visible*.
    fn confirm_first_keystroke() -> (PredictionEngine, Screen) {
        let mut e = PredictionEngine::new(DisplayPreference::Always);
        e.set_local_frame_sent(0);
        let blank = screen_of(b"");
        type_bytes(&mut e, &blank, b"x");
        assert!(
            e.overlay().is_empty(),
            "the very first keystroke must be hidden until the server confirms it echoes"
        );
        let echoed = screen_of(b"x");
        e.set_local_frame_late_acked(1);
        e.cull(&echoed); // grades 'x' Correct -> confirmed_epoch = 1
        (e, echoed)
    }

    #[test]
    fn predictions_hidden_until_server_confirms_echo() {
        // P0 (security): a secret typed before ANY server confirmation must never be drawn,
        // even with Display::Always.
        let mut e = PredictionEngine::new(DisplayPreference::Always);
        e.set_local_frame_sent(0);
        let blank = screen_of(b"");
        type_bytes(&mut e, &blank, b"hunter2");
        assert!(
            e.overlay().is_empty(),
            "predictions must stay hidden until the server confirms it echoes"
        );
    }

    #[test]
    fn confirmed_echo_makes_subsequent_typing_visible() {
        // After the server proves it echoes (one Correct), later typing in the confirmed epoch shows.
        let (mut e, echoed) = confirm_first_keystroke();
        e.set_local_frame_sent(1);
        type_bytes(&mut e, &echoed, b"y"); // cursor now at (0,1)
        let ov = e.overlay();
        assert_eq!(
            ov.cell(0, 1).map(|c| c.glyph),
            Some("y"),
            "typing after confirmation must be visible"
        );
    }

    #[test]
    fn no_echo_keeps_secret_hidden_and_cleans_up() {
        // Password-prompt style: the server never echoes -> never shown, then culled away.
        let mut e = PredictionEngine::new(DisplayPreference::Always);
        e.set_local_frame_sent(0);
        let blank = screen_of(b"");
        type_bytes(&mut e, &blank, b"s");
        assert!(e.overlay().is_empty(), "non-echoed input is never shown");

        let still_blank = screen_of(b"");
        e.set_local_frame_late_acked(1);
        e.cull(&still_blank);
        assert!(
            e.overlay().is_empty(),
            "non-echoed input must not leave a predicted glyph"
        );
    }

    #[test]
    fn never_mode_predicts_nothing() {
        let mut e = PredictionEngine::new(DisplayPreference::Never);
        let screen = screen_of(b"");
        type_bytes(&mut e, &screen, b"x");
        assert!(e.overlay().is_empty());
    }

    #[test]
    fn insert_mode_shifts_row_right() {
        // Screen "ab" with the cursor on 'b' (col 1). Typing 'X' should INSERT before 'b',
        // shifting the tail right — not overwrite 'b'. (Inspect predicted cells directly; the
        // epoch gate hides them from overlay() until confirmed, but the shift populates cells.)
        let mut e = PredictionEngine::new(DisplayPreference::Always);
        e.set_local_frame_sent(0);
        let screen = screen_of(b"ab\x1b[1;2H"); // cursor -> row1 col2 = (0,1)
        type_bytes(&mut e, &screen, b"X");
        assert_eq!(
            e.cells.get(&(0, 1)).map(|c| c.glyph.as_str()),
            Some("X"),
            "typed char at col"
        );
        assert_eq!(
            e.cells.get(&(0, 2)).map(|c| c.glyph.as_str()),
            Some("b"),
            "tail shifted right"
        );
    }

    #[test]
    fn insert_mode_backspace_shifts_left_with_unknown_right_edge() {
        // Screen "abc" cursor on 'c' (col 2). Backspace deletes 'b': 'c' shifts left to col 1,
        // and the last TWO columns become unknown (content scrolled in from off-screen; mosh marks
        // the cell unknown when `i + 2 >= width`, so both edge columns, not just the last one).
        let mut e = PredictionEngine::new(DisplayPreference::Always);
        e.set_local_frame_sent(0);
        let screen = screen_of(b"abc\x1b[1;3H"); // cursor -> (0,2)
        type_bytes(&mut e, &screen, &[0x7f]); // backspace
        let (_, cols) = screen.size();
        assert_eq!(
            e.cells.get(&(0, 1)).map(|c| c.glyph.as_str()),
            Some("c"),
            "tail shifted left"
        );
        assert!(
            e.cells.get(&(0, cols - 1)).is_some_and(|c| c.unknown),
            "the last column is marked unknown after a mid-line backspace"
        );
        assert!(
            e.cells.get(&(0, cols - 2)).is_some_and(|c| c.unknown),
            "the second-to-last column is unknown too (mosh's `i + 2 >= width`)"
        );
        assert!(
            e.cells.get(&(0, cols - 3)).is_some_and(|c| !c.unknown),
            "the third-to-last column is still a concrete shifted cell, not unknown"
        );
    }

    #[test]
    fn insert_mode_backspace_does_not_overflow_at_max_width() {
        // The unknown-column guard must be overflow-safe on a peer-controlled width.
        // At cols == u16::MAX the left-shift loop reaches i = 65534, where a naive `i + 2` overflows
        // u16 (panics under debug overflow-checks). The `i < cols - 2` form must not.
        let p = fux_vt::Parser::new(1, u16::MAX, 0).expect("1-row parser");
        let mut e = PredictionEngine::new(DisplayPreference::Always);
        e.set_local_frame_sent(0);
        // Predicted cursor near the right edge so the backspace runs its left-shift loop out to the
        // final column (where the overflow would occur).
        e.cursor = Some(PredCursor {
            expiration_frame: 1,
            tentative_epoch: 1,
            row: 0,
            col: u16::MAX - 1,
        });
        type_bytes(&mut e, p.screen(), &[0x7f]); // backspace — must not panic
                                                 // The two right-edge columns are unknown (mosh's `i + 2 >= width`), with no `i + 1` read.
        assert!(
            e.cells.get(&(0, u16::MAX - 1)).is_some_and(|c| c.unknown),
            "last column unknown at max width"
        );
        assert!(
            e.cells.get(&(0, u16::MAX - 2)).is_some_and(|c| c.unknown),
            "second-to-last column unknown at max width"
        );
    }

    #[test]
    fn correct_grade_recolors_rest_of_row_pending_predictions() {
        // mosh "match rest of row to the actual renditions": when a predicted cell confirms with a
        // concrete on-screen color, the still-pending predicted cells to its right adopt that color
        // (so they don't flash a guessed rendition before their own frame confirms).
        let mut e = PredictionEngine::new(DisplayPreference::Always);
        e.set_local_frame_sent(0);
        // Confirm an initial keystroke so later predictions are in a shown epoch.
        let blank = screen_of(b"");
        type_bytes(&mut e, &blank, b"a");
        let echoed = screen_of(b"a");
        e.set_local_frame_late_acked(1);
        e.cull(&echoed); // confirmed_epoch = 1

        // Type "bc": 'b' on frame 2 (will be confirmed), 'c' on frame 3 (stays pending), so 'c'
        // survives the cull where 'b' confirms — and can be recolored.
        e.set_local_frame_sent(1);
        type_bytes(&mut e, &echoed, b"b");
        e.set_local_frame_sent(2);
        type_bytes(&mut e, &echoed, b"c");
        assert_eq!(
            e.cells.get(&(0, 2)).map(|c| c.fg),
            Some(Color::Default),
            "'c' starts with the default (guessed) foreground"
        );

        // The server echoes 'b' in a *colored* rendition (red fg) and acks frame 2; 'c' (frame 3)
        // is still pending. Grading 'b' Correct must repaint the rest of the row — col 2's pending
        // 'c' — with 'b''s actual red foreground.
        let colored = screen_of(b"a\x1b[31mb");
        e.set_local_frame_late_acked(2);
        e.cull(&colored);
        assert_eq!(
            e.cells.get(&(0, 2)).map(|c| c.fg),
            Some(Color::Idx(1)),
            "the pending 'c' adopted the confirmed 'b' cell's actual red foreground"
        );
    }

    #[test]
    fn killed_epoch_reseeds_cursor_off_stale_position() {
        // A tentative-epoch mispredict kills that epoch. mosh's kill_epoch re-seeds the cursor at
        // the real screen position so a *confirmed-but-stale* predicted cursor — one that would
        // otherwise keep being drawn at a position the killed predictions had moved it to — is
        // displaced. Built from raw state to isolate exactly that condition.
        let mut e = PredictionEngine::new(DisplayPreference::Always);
        e.confirmed_epoch = 1;
        e.prediction_epoch = 2;
        e.set_local_frame_sent(5);
        e.set_local_frame_late_acked(5);
        // A CONFIRMED (epoch 1 <= confirmed 1) cursor at a stale column, still Pending (expiration
        // far ahead of late_acked) so the validation pass won't resolve it — it would keep drawing.
        e.cursor = Some(PredCursor {
            expiration_frame: 99,
            tentative_epoch: 1,
            row: 0,
            col: 9,
        });
        // A TENTATIVE cell (epoch 2 > confirmed 1) the next frame contradicts -> kills epoch 2.
        e.cells.insert(
            (0, 3),
            PredCell {
                expiration_frame: 5,
                tentative_epoch: 2,
                glyph: "Q".to_string(),
                fg: Color::Default,
                bg: Color::Default,
                original_contents: Some(String::new()),
                unknown: false,
                wide: false,
                covered: false,
            },
        );
        let blank = screen_of(b"");
        assert_eq!(
            e.overlay().cursor(),
            Some((0, 9)),
            "the stale confirmed cursor is drawn before the kill"
        );
        // The frame has no 'Q' at (0,3) -> epoch 2 is killed; the real cursor is at (0,0).
        e.cull(&blank);
        assert!(
            e.overlay().cursor().is_none(),
            "after kill_epoch the stale predicted cursor is displaced; the real cursor shows through"
        );
        let c = e
            .cursor
            .as_ref()
            .expect("kill_epoch re-seeds a cursor rather than clearing it");
        assert_eq!(
            (c.row, c.col),
            (0, 0),
            "the re-seeded cursor sits at the real screen position"
        );
    }

    #[test]
    fn left_arrow_predicts_cursor_and_leaves_no_glyph() {
        // After confirming a keystroke (cursor at (0,1)), a left arrow predicts the cursor one
        // column left and must NOT leave literal '[' / 'D' glyphs from the escape bytes.
        let (mut e, echoed) = confirm_first_keystroke();
        e.set_local_frame_sent(1);
        type_bytes(&mut e, &echoed, b"\x1b[D");
        let ov = e.overlay();
        assert_eq!(
            ov.cursor(),
            Some((0, 0)),
            "left arrow predicts the cursor one col left"
        );
        assert!(
            ov.cell(0, 0).is_none() && ov.cell(0, 1).is_none(),
            "arrow escape bytes must not be drawn as literal glyphs"
        );
    }

    #[test]
    fn ss3_left_arrow_is_normalized_and_predicted() {
        // Application-cursor-mode arrow: ESC O D must behave like ESC [ D.
        let (mut e, echoed) = confirm_first_keystroke();
        e.set_local_frame_sent(1);
        type_bytes(&mut e, &echoed, b"\x1bOD");
        assert_eq!(e.overlay().cursor(), Some((0, 0)));
    }

    #[test]
    fn double_width_grapheme_predicted_and_advances_cursor_by_two() {
        // A CJK character is double-width: its multi-byte UTF-8 arrives one byte at a time and is
        // reassembled into a single predicted glyph, with the cursor stepping forward two cells
        // (and no stray glyph in the continuation cell).
        let (mut e, echoed) = confirm_first_keystroke();
        e.set_local_frame_sent(1);
        type_bytes(&mut e, &echoed, "世".as_bytes());
        let ov = e.overlay();
        assert_eq!(
            ov.cell(0, 1).map(|c| c.glyph),
            Some("世"),
            "the wide grapheme is predicted at the cursor column"
        );
        assert!(
            ov.cell(0, 2)
                .is_some_and(|c| c.covered && c.glyph.is_empty()),
            "the continuation cell of a wide char is covered, with no predicted glyph of its own"
        );
        assert_eq!(
            ov.cursor(),
            Some((0, 3)),
            "cursor advances by two cells for a double-width char"
        );
    }

    /// A screen of `rows`×`cols` showing `bytes`.
    fn sized_screen_of(rows: u16, cols: u16, bytes: &[u8]) -> Screen {
        let mut p = fux_vt::Parser::new(rows, cols, 0).expect("parser");
        p.process(bytes).expect("process");
        p.screen().clone()
    }

    /// What is predicted at `(0, col)`: the glyph, `U` for unknown, `>` for a covered cell.
    fn predicted_at(e: &PredictionEngine, col: u16) -> Option<String> {
        e.cells.get(&(0, col)).map(|c| {
            if c.unknown {
                "U".to_owned()
            } else if c.covered {
                ">".to_owned()
            } else {
                c.glyph.clone()
            }
        })
    }

    #[test]
    fn inserting_before_a_wide_glyph_moves_it_whole() {
        let mut e = PredictionEngine::new(DisplayPreference::Always);
        e.set_local_frame_sent(0);
        let screen = screen_of("a本b\x1b[1;1H".as_bytes());
        type_bytes(&mut e, &screen, b"X");
        let row: Vec<_> = (0..5).map(|col| predicted_at(&e, col)).collect();
        let expected = ["X", "a", "本", ">", "b"].map(|g| Some(g.to_owned()));
        assert_eq!(row, expected);
        assert!(e.cells.get(&(0, 2)).is_some_and(|c| c.wide));
    }

    #[test]
    fn a_wide_glyph_split_by_a_shift_is_unknown() {
        // Pushed to the edge, its right half would leave the screen.
        let mut e = PredictionEngine::new(DisplayPreference::Always);
        e.set_local_frame_sent(0);
        let screen = sized_screen_of(2, 6, "abc本\x1b[1;1H".as_bytes());
        type_bytes(&mut e, &screen, b"X");
        assert_eq!(predicted_at(&e, 4).as_deref(), Some("U"), "its glyph");
        assert_eq!(predicted_at(&e, 5).as_deref(), Some("U"), "its right half");
        // Typed inside one, its halves part.
        let mut e = PredictionEngine::new(DisplayPreference::Always);
        e.set_local_frame_sent(0);
        let screen = screen_of("本x\x1b[1;2H".as_bytes());
        type_bytes(&mut e, &screen, b"a");
        assert_eq!(predicted_at(&e, 1).as_deref(), Some("a"));
        assert_eq!(
            predicted_at(&e, 2).as_deref(),
            Some("U"),
            "the moved right half"
        );
        // Deleting before one moves it left, whole.
        let mut e = PredictionEngine::new(DisplayPreference::Always);
        e.set_local_frame_sent(0);
        let screen = screen_of("ab本c\x1b[1;3H".as_bytes());
        type_bytes(&mut e, &screen, &[0x7f]);
        let row: Vec<_> = (1..4).map(|col| predicted_at(&e, col)).collect();
        assert_eq!(row, ["本", ">", "c"].map(|g| Some(g.to_owned())));
    }

    #[test]
    fn a_wide_glyph_typed_over_another_wide_glyph_s_half_leaves_no_half() {
        // Typed over the right half of a predicted wide glyph: that glyph cannot show.
        let (mut e, echoed) = confirm_first_keystroke();
        e.set_local_frame_sent(1);
        type_bytes(&mut e, &echoed, "日".as_bytes());
        e.cursor = e.cursor.clone().map(|c| PredCursor { col: 2, ..c });
        type_bytes(&mut e, &echoed, "本".as_bytes());
        let row: Vec<_> = (1..5).map(|col| predicted_at(&e, col)).collect();
        assert_eq!(
            row,
            ["U", "本", ">"]
                .map(|g| Some(g.to_owned()))
                .into_iter()
                .chain([None])
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn backspace_over_a_wide_glyph_is_not_predicted() {
        // A line editor deletes both halves: not modelled, so a new epoch and nothing predicted.
        let (mut e, _) = confirm_first_keystroke();
        let screen = screen_of("x本".as_bytes());
        e.set_local_frame_sent(1);
        let epoch = e.prediction_epoch;
        type_bytes(&mut e, &screen, &[0x7f]);
        assert!(e.cells.is_empty(), "nothing predicted");
        assert!(e.prediction_epoch > epoch, "a new epoch");
        assert!(e.overlay().is_empty());
    }

    #[test]
    fn a_covered_cell_is_graded_against_a_right_half_and_confirms_nothing() {
        let covered = PredCell {
            expiration_frame: 1,
            tentative_epoch: 1,
            glyph: String::new(),
            fg: Color::Default,
            bg: Color::Default,
            original_contents: Some(String::new()),
            unknown: false,
            wide: false,
            covered: true,
        };
        let wide = screen_of("x本".as_bytes());
        let narrow = screen_of(b"xab");
        assert!(
            cell_validity(&covered, &wide, 0, 2, 24, 80, 1) == Validity::CorrectNoCredit,
            "a right half where it was predicted: right, but no credit"
        );
        assert!(
            cell_validity(&covered, &narrow, 0, 2, 24, 80, 1) == Validity::IncorrectOrExpired,
            "a narrow glyph where a right half was predicted: wrong"
        );
        assert!(
            cell_validity(&covered, &narrow, 0, 2, 24, 80, 0) == Validity::Pending,
            "before its frame"
        );
    }

    #[test]
    fn prediction_reassembles_multibyte_utf8_no_stray_byte() {
        // mosh prediction-unicode regression: typing "glück" must predict 'ü', and "faĩl" 'ĩ' —
        // NOT the low byte of the code point (mosh, being char/byte based, would briefly draw the
        // low 8 bits: a raw 0xFC, or ')' for ĩ's 0x129 & 0xFF = 0x29, before the server corrected
        // it). koh reassembles the whole UTF-8 grapheme before predicting, so the predicted
        // glyph is always the real character. (`)` is the meaningful char-level artifact; ü's raw
        // 0xFC can't even exist in a Rust `String`, so reassembly itself is the guarantee.)
        for (word, accent) in [("glück", "ü"), ("faĩl", "ĩ")] {
            let (mut e, echoed) = confirm_first_keystroke();
            e.set_local_frame_sent(1);
            type_bytes(&mut e, &echoed, word.as_bytes());
            let ov = e.overlay();
            // The first typed char lands at col 1 (cursor seeded from the echoed "x"); the accent
            // is the 3rd char, so column 3.
            assert_eq!(
                ov.cell(0, 3).map(|c| c.glyph),
                Some(accent),
                "{word}: accented char must be predicted as the real grapheme"
            );
            for col in 0..80u16 {
                if let Some(cell) = ov.cell(0, col) {
                    assert_ne!(
                        cell.glyph, ")",
                        "{word}: ĩ must not collapse to its low byte ')'"
                    );
                }
            }
        }
    }

    /// A predictor trusted at a line editor (no kernel echo, no line mode), on `bytes`' screen.
    fn editor_on(bytes: &[u8]) -> (PredictionEngine, Screen) {
        let mut e = PredictionEngine::new(DisplayPreference::Always);
        let screen = screen_of(bytes);
        e.carried = true;
        e.set_tty(Some(TtyModes {
            echo: false,
            line: false,
        }));
        e.cull(&screen);
        (e, screen)
    }

    /// Type `keys` into `e` over `screen`, as one input frame.
    fn type_keys(e: &mut PredictionEngine, screen: &Screen, keys: &[u8]) {
        e.set_local_frame_sent(1);
        type_bytes(e, screen, keys);
    }

    /// Row 0 as shown: the overlay over the screen, trailing blanks trimmed; and the cursor's
    /// column as predicted.
    fn shown_row(e: &PredictionEngine, screen: &Screen) -> (String, Option<u16>) {
        let ov = e.overlay();
        let text: String = (0..80)
            .map(|col| match ov.cell(0, col) {
                Some(cell) => cell.glyph.to_owned(),
                None => cell_glyph(screen, 0, col),
            })
            .map(|g| if g.is_empty() { " ".to_owned() } else { g })
            .collect();
        (text.trim_end().to_owned(), ov.cursor().map(|(_, c)| c))
    }

    #[test]
    fn ctrl_w_deletes_the_word_before_the_cursor_and_never_the_prompt() {
        let (mut e, screen) = editor_on(b"$ git commit -m msg");
        type_keys(&mut e, &screen, &[0x17]);
        assert_eq!(
            shown_row(&e, &screen),
            ("$ git commit -m".to_owned(), Some(16))
        );
        type_keys(&mut e, &screen, &[0x17]);
        assert_eq!(shown_row(&e, &screen).0, "$ git commit");
        // An empty line: the word left of the cursor is the prompt's, which is not the line's.
        let (mut e, screen) = editor_on(b"$ ");
        type_keys(&mut e, &screen, &[0x17]);
        assert!(e.overlay().is_empty(), "nothing predicted");
    }

    #[test]
    fn alt_backspace_deletes_back_to_punctuation() {
        let (mut e, screen) = editor_on(b"$ cd /usr/lib");
        type_keys(&mut e, &screen, b"\x1b\x7f");
        assert_eq!(shown_row(&e, &screen), ("$ cd /usr/".to_owned(), Some(10)));
    }

    #[test]
    fn ctrl_u_and_ctrl_a_go_to_where_the_line_began_only_when_it_is_known() {
        let (mut e, screen) = editor_on(b"$ ls -l");
        type_keys(&mut e, &screen, &[0x15]);
        assert!(e.overlay().is_empty(), "where the line began is not known");
        // Typed after Enter, the line's start is known.
        let (mut e, screen) = editor_on(b"$ ");
        e.fresh_line = true;
        type_keys(&mut e, &screen, b"echo hi");
        assert_eq!(shown_row(&e, &screen), ("$ echo hi".to_owned(), Some(9)));
        type_keys(&mut e, &screen, &[0x01]);
        assert_eq!(shown_row(&e, &screen).1, Some(2), "Ctrl-A");
        type_keys(&mut e, &screen, &[0x05]);
        assert_eq!(shown_row(&e, &screen).1, Some(9), "Ctrl-E");
        type_keys(&mut e, &screen, &[0x15]);
        assert_eq!(shown_row(&e, &screen), ("$".to_owned(), Some(2)), "Ctrl-U");
    }

    #[test]
    fn home_end_and_word_motion_move_the_cursor_only() {
        let (mut e, screen) = editor_on(b"$ make test\x1b[2D");
        type_keys(&mut e, &screen, b"\x1b[F");
        assert_eq!(
            shown_row(&e, &screen),
            ("$ make test".to_owned(), Some(11)),
            "End"
        );
        type_keys(&mut e, &screen, b"\x1bb");
        assert_eq!(
            shown_row(&e, &screen).1,
            Some(7),
            "Alt-B: the start of test"
        );
        type_keys(&mut e, &screen, b"\x1bb");
        assert_eq!(
            shown_row(&e, &screen).1,
            Some(2),
            "Alt-B: the start of make"
        );
        type_keys(&mut e, &screen, b"\x1bf");
        assert_eq!(shown_row(&e, &screen).1, Some(6), "Alt-F: the end of make");
        // Home with the line's start unknown: not predicted; the cursor stays where it was.
        type_keys(&mut e, &screen, b"\x1b[1~");
        assert_eq!(shown_row(&e, &screen).1, Some(6));
    }

    #[test]
    fn a_csi_with_parameters_is_read_whole_and_draws_nothing() {
        let (mut e, screen) = editor_on(b"$ ab");
        type_keys(&mut e, &screen, b"\x1b[3~\x1b[1;5C");
        let (text, _) = shown_row(&e, &screen);
        assert_eq!(text, "$ ab", "no '~' or 'C' drawn");
    }

    #[test]
    fn a_password_prompt_shows_nothing_typed_even_after_trust() {
        let (mut e, screen) = editor_on(b"$ ");
        type_keys(&mut e, &screen, b"sudo");
        assert!(!e.overlay().is_empty(), "trusted at the shell");
        // sudo turns echo off and reads a line: whatever was trusted, nothing shows.
        let prompt = screen_of(b"$ sudo\r\n[sudo] password for me: ");
        e.set_tty(Some(TtyModes {
            echo: false,
            line: true,
        }));
        e.cull(&prompt);
        type_keys(&mut e, &prompt, b"hunter2");
        assert!(e.overlay().is_empty());
        assert!(e.cells.is_empty(), "nothing even kept");
        // Carried trust is not given at one either.
        let mut fresh = PredictionEngine::new(DisplayPreference::Always);
        fresh.carried = true;
        fresh.set_tty(Some(TtyModes {
            echo: false,
            line: true,
        }));
        type_keys(&mut fresh, &prompt, b"hunter2");
        assert!(fresh.overlay().is_empty());
    }

    #[test]
    fn kernel_echo_is_trusted_from_the_first_key() {
        let mut e = PredictionEngine::new(DisplayPreference::Always);
        let screen = screen_of(b"");
        e.set_tty(Some(TtyModes {
            echo: true,
            line: true,
        }));
        type_keys(&mut e, &screen, b"hi");
        assert_eq!(shown_row(&e, &screen), ("hi".to_owned(), Some(2)));
        // Without echo known, the first key waits for the server, as before.
        let mut e = PredictionEngine::new(DisplayPreference::Always);
        type_keys(&mut e, &screen, b"hi");
        assert!(e.overlay().is_empty());
    }

    #[test]
    fn trust_carried_from_a_reconnect_shows_the_first_key() {
        let (mut e, screen) = editor_on(b"$ ");
        type_keys(&mut e, &screen, b"l");
        assert_eq!(shown_row(&e, &screen).0, "$ l");
    }
}

#[cfg(test)]
mod key_reparse_tests {
    use super::*;

    use fux_vt::keys::Key;
    use fux_vt::Screen;

    fn editor_on(bytes: &[u8]) -> (PredictionEngine, Screen) {
        let mut p = fux_vt::Parser::new(24, 80, 0).expect("24x80 parser");
        p.process(bytes).expect("process");
        let screen = p.screen().clone();
        let mut e = PredictionEngine::new(DisplayPreference::Always);
        e.carried = true;
        e.set_tty(Some(TtyModes {
            echo: false,
            line: false,
        }));
        e.cull(&screen);
        e.set_local_frame_sent(1);
        (e, screen)
    }

    fn key(c: char) -> KeyPress {
        KeyPress::plain(Key::Char(c))
    }

    /// Escape, then `O`, then `D`, each its own key press, are three keys, not the
    /// application-cursor-mode Left arrow `ESC O D`: the predictor must not move the cursor
    /// left over `c`.
    #[test]
    fn separate_escape_o_d_keys_are_not_a_left_arrow() {
        let (mut e, screen) = editor_on(b"$ abc");
        e.new_user_key(KeyPress::plain(Key::Escape), &screen);
        e.new_user_key(key('O'), &screen);
        e.new_user_key(key('D'), &screen);
        let ov = e.overlay();
        assert_ne!(
            ov.cursor(),
            Some((0, 4)),
            "three separate keys (Escape, 'O', 'D') were predicted as a Left arrow"
        );
    }

    /// Escape, then a focus event (input the predictor does not model), then `b`: the `b` is
    /// not Alt-B. The predictor must not move the cursor back to the start of the word.
    #[test]
    fn escape_then_focus_event_then_b_is_not_alt_b() {
        let (mut e, screen) = editor_on(b"$ make test");
        e.new_user_key(KeyPress::plain(Key::Escape), &screen);
        e.new_user_other(&screen);
        e.new_user_key(key('b'), &screen);
        // The focus event opened a new epoch, so the overlay hides what is predicted until the
        // server confirms it; read the prediction itself, which is what is shown on confirm.
        let predicted_cursor = e.cursor.as_ref().map(|c| (c.row, c.col));
        assert_ne!(
            predicted_cursor,
            Some((0, 7)),
            "Escape, a focus event, then 'b' was predicted as Alt-B (word motion)"
        );
        assert!(
            e.cells.get(&(0, 11)).is_some_and(|c| c.glyph == "b"),
            "'b' typed after a focus event is not predicted as a 'b' glyph at the cursor"
        );
    }
}
