//! Local-echo prediction: the client guesses what each keystroke does to the screen and shows it at
//! once, then confirms or corrects it when the server's frame arrives.
//!
//! Guesses are grouped in epochs, confirmed by the server's echo-ack, so input a program does not
//! echo (a password) is never shown. Only edit keys reach it, and only in a `Context`: on the
//! primary screen, with the PTY's modes known and not a password prompt, so a full-screen program
//! (or tmux's and screen's prefix keys) is never taken for a line editor. It predicts printable
//! graphemes (wide ones included, and one glyph for a grapheme however many keys typed it),
//! Backspace, Enter, Left and Right, and readline's line and word keys; anything else opens a new
//! epoch and waits for the server. A guess is a real cell, with the style of the cell it copies or,
//! for a typed glyph, of its left neighbour. A wrong guess is reconciled away, never left on
//! screen. The renderer draws an [`Overlay`].

use std::collections::{BTreeMap, BTreeSet};

use fux_vt::keys::{Direction, Key, KeyPress, Modifiers};
use fux_vt::{Attributes, CellRef};

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

/// The screen the predictor reconciles against: the client's grid, or a test's. A trait, so
/// `predict` imports nothing from `crate::` (CI checks).
pub trait ScreenView {
    fn size(&self) -> Size;
    /// The cursor as `(row, col)`, 0-indexed.
    fn cursor_position(&self) -> (u16, u16);
    /// The cell at `(row, col)`, or `None` when out of bounds.
    fn cell(&self, row: u16, col: u16) -> Option<CellRef<'_>>;
    /// Whether the alternate screen is shown, as full-screen programs (and tmux, screen) show it.
    fn alternate(&self) -> bool;
}

/// Which part of a glyph a cell holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Half {
    Narrow,
    /// A wide glyph, whose right half is the next cell.
    Wide,
    /// The right half of the wide glyph to its left: nothing of its own to draw.
    Covered,
}

/// A cell as a prediction says it is: its glyph (empty for a blank), its full style, and which
/// part of a glyph it holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cell {
    text: String,
    attributes: Attributes,
    half: Half,
}

impl Cell {
    /// A copy of `cell`.
    fn of(cell: CellRef<'_>) -> Self {
        let half = if cell.is_wide_continuation() {
            Half::Covered
        } else if cell.is_wide() {
            Half::Wide
        } else {
            Half::Narrow
        };
        Self {
            text: cell.contents().to_owned(),
            attributes: cell.attributes(),
            half,
        }
    }

    /// The cell as a screen's: a covered one as the right half of a wide glyph.
    pub fn as_ref(&self) -> CellRef<'_> {
        match self.half {
            Half::Covered => CellRef::wide_continuation(),
            Half::Narrow | Half::Wide => {
                CellRef::new(&self.text, self.half == Half::Wide, self.attributes)
            }
        }
    }

    /// Its glyph: empty for a blank or a covered cell.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Its style, a covered cell's its glyph's.
    pub const fn attributes(&self) -> Attributes {
        self.attributes
    }

    pub fn covered(&self) -> bool {
        self.half == Half::Covered
    }
}

/// What to draw over the authoritative grid: the predictions shown, and the cursor.
///
/// A wide glyph is predicted in two cells, the glyph and the covered cell to its right. A cell the
/// predictor knows changed, but not to what, is left out, so the real cell shows.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct Overlay {
    cells: BTreeMap<(u16, u16), Cell>,
    cursor: Option<(u16, u16)>,
}

impl Overlay {
    /// An overlay of exactly `cells` (their texts, wide if `wide`, in `attributes`; each wide one
    /// covering the next cell when `covering`) and `cursor`, for tests of what draws it.
    #[cfg(test)]
    pub(crate) fn of<'t>(
        cells: impl IntoIterator<Item = ((u16, u16), &'t str, Attributes, bool)>,
        cursor: Option<(u16, u16)>,
    ) -> Self {
        let mut out = Self {
            cells: BTreeMap::new(),
            cursor,
        };
        for ((row, col), text, attributes, covering) in cells {
            let wide = text.width() == 2;
            let half = if wide && covering {
                Half::Wide
            } else {
                Half::Narrow
            };
            let cell = |text: &str, half| Cell {
                text: text.to_owned(),
                attributes,
                half,
            };
            out.cells.insert((row, col), cell(text, half));
            if let Some(next) = col.checked_add(1).filter(|_| half == Half::Wide) {
                out.cells.insert((row, next), cell("", Half::Covered));
            }
        }
        out
    }
    /// The predicted cell at `(row, col)`, if any.
    pub fn cell(&self, row: u16, col: u16) -> Option<&Cell> {
        self.cells.get(&(row, col))
    }
    /// Every predicted cell, in `(row, col)` order.
    pub fn cells(&self) -> impl Iterator<Item = ((u16, u16), &Cell)> + '_ {
        self.cells.iter().map(|(&at, cell)| (at, cell))
    }
    /// The predicted cells on `row`, by column.
    pub fn row(&self, row: u16) -> impl Iterator<Item = (u16, &Cell)> + '_ {
        self.cells
            .range((row, 0)..=(row, u16::MAX))
            .map(|(&(_, col), cell)| (col, cell))
    }
    /// The predicted cursor position `(row, col)`, if any.
    pub const fn cursor(&self) -> Option<(u16, u16)> {
        self.cursor
    }
    pub fn is_empty(&self) -> bool {
        self.cells.is_empty() && self.cursor.is_none()
    }
}

/// A prediction for one cell, stamped with when it is graded and the epoch that hides it.
#[derive(Clone)]
struct PredCell {
    expiration_frame: u64,
    tentative_epoch: u64,
    /// What the cell shows, or `None` when it changed to something not known: never drawn.
    guess: Option<Cell>,
    /// The glyph this overwrote, so a rewrite back to it cannot confirm an epoch.
    original: String,
    /// The typed glyph (or its right half), whose style was borrowed from its neighbour: the cell
    /// a confirmed echo recolours.
    typed: bool,
}

/// Where a frame showed the cursor: the only position a line can be taken to begin at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Confirmed {
    row: u16,
    col: u16,
}

impl Confirmed {
    fn of(screen: &dyn ScreenView) -> Self {
        let (row, col) = screen.cursor_position();
        Self { row, col }
    }
}

/// Where the predictions put the cursor, until a frame grades it.
#[derive(Clone)]
struct Guessed {
    expiration_frame: u64,
    tentative_epoch: u64,
    row: u16,
    col: u16,
}

/// What is known of the line being typed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Line {
    Unknown,
    /// Enter was typed, in the input frame `.0`: the line begins where the screen shows the
    /// cursor when its first key is typed, if the screen has reflected the Enter by then and no
    /// guess is pending.
    Fresh(u64),
    /// The line began at a cursor a frame showed. Keys that go to its start (`Ctrl-A`, Home,
    /// `Ctrl-U`) are predicted only then, and Backspace and Left never past it.
    Started(Confirmed),
}

#[derive(PartialEq, Eq)]
enum Validity {
    Pending,
    Correct,
    CorrectNoCredit,
    IncorrectOrExpired,
}

/// What a key is predicted against: a screen on the primary screen whose PTY's modes are known
/// and are not a password prompt. Only [`PredictionEngine::context`] makes one.
struct Context<'a> {
    screen: &'a dyn ScreenView,
    tty: TtyModes,
    size: Size,
}

impl Context<'_> {
    /// Whether line editing keys may be predicted: a line editor reads keys (no kernel echo,
    /// which edits a line its own way).
    const fn editing(&self) -> bool {
        !self.tty.echo
    }
}

/// The prediction engine.
///
/// Call [`set_local_frame_sent`](Self::set_local_frame_sent) before each typed key and
/// [`new_user_key`](Self::new_user_key) for it;
/// [`set_local_frame_late_acked`](Self::set_local_frame_late_acked), [`set_tty`](Self::set_tty)
/// and [`cull`](Self::cull) on a frame; [`overlay`](Self::overlay) to render.
pub struct PredictionEngine {
    cells: BTreeMap<(u16, u16), PredCell>,
    cursor: Option<Guessed>,
    prediction_epoch: u64,
    confirmed_epoch: u64,
    local_frame_sent: u64,
    late_acked: u64,
    /// The newest input frame [`hold`](Self::hold) held: nothing is predicted until the server
    /// has reflected it, so no held key shows and nothing is guessed from a model that lacks it.
    held_through: Option<u64>,
    last_size: Option<Size>,
    /// How the program's PTY takes typed keys, as the newest frame said.
    tty: Option<TtyModes>,
    /// Trust from the last connection to the same session, given once a frame shows known modes
    /// that are not a password prompt.
    carried: bool,
    line: Line,
}

impl Default for PredictionEngine {
    /// A predictor that has seen nothing.
    fn default() -> Self {
        Self {
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
            tty: None,
            carried: false,
            line: Line::Unknown,
        }
    }
}

impl PredictionEngine {
    /// A fresh engine for a reconnect to the same session: if typing was being shown as it was
    /// predicted (or trust was carried here and not yet given), trust from the first key once a
    /// frame shows known modes that are not a password prompt ([`set_tty`](Self::set_tty)).
    /// Taken once, at an outage's first drop, the trust is the drop's: nothing until the next
    /// frame confirms an epoch, so nothing typed then can add to it.
    #[must_use]
    pub fn reattached(&self) -> Self {
        Self {
            carried: self.carried || self.prediction_epoch == self.confirmed_epoch,
            ..Self::default()
        }
    }

    /// How the program's PTY takes typed keys, as a frame said.
    ///
    /// At a password prompt (lines read without echo) nothing is predicted and every prediction
    /// goes: a typed secret is never shown, whatever was confirmed before. At known modes that are
    /// not one, carried trust is given; unknown modes give nothing.
    pub fn set_tty(&mut self, tty: Option<TtyModes>) {
        self.tty = tty;
        match tty {
            Some(tty) if tty.password() => {
                if !self.cells.is_empty() || self.cursor.is_some() {
                    self.reset();
                }
                self.carried = false;
            }
            Some(_) if std::mem::take(&mut self.carried) => {
                self.confirmed_epoch = self.confirmed_epoch.max(self.prediction_epoch);
            }
            Some(_) | None => {}
        }
    }

    /// What a key may be predicted against on `screen`: nothing on the alternate screen, with the
    /// PTY's modes unknown, at a password prompt, or on an empty screen.
    fn context<'a>(&self, screen: &'a dyn ScreenView) -> Option<Context<'a>> {
        let size = screen.size();
        let tty = self.tty.filter(|tty| !tty.password())?;
        (!screen.alternate() && size.rows > 0 && size.cols > 0).then_some(Context {
            screen,
            tty,
            size,
        })
    }

    /// What a cell shows, predicted if there is a prediction: what a row shift copies, a wide
    /// glyph's halves included. `None` if it is not known.
    fn guess_at(&self, ctx: &Context<'_>, row: u16, col: u16) -> Option<Cell> {
        self.cells.get(&(row, col)).map_or_else(
            || ctx.screen.cell(row, col).map(Cell::of),
            |p| p.guess.clone(),
        )
    }

    /// Predict `guess` at `(row, col)`, stamped with the next frame, the current epoch (which hides
    /// it until confirmed) and the glyph it overwrites. One place, so no caller can get the
    /// security-relevant stamps wrong.
    fn place(
        &mut self,
        ctx: &Context<'_>,
        (row, col): (u16, u16),
        guess: Option<Cell>,
        typed: bool,
    ) {
        let original = ctx
            .screen
            .cell(row, col)
            .map(|c| c.contents().to_owned())
            .unwrap_or_default();
        self.cells.insert(
            (row, col),
            PredCell {
                expiration_frame: self.next_frame(),
                tentative_epoch: self.prediction_epoch,
                guess,
                original,
                typed,
            },
        );
    }

    /// Keep each predicted wide glyph on `row` with its right half: a wide glyph whose right half
    /// is not the next cell's prediction, or a right half whose glyph is not the cell to its left,
    /// was split (by a shift at the edge, or an edit inside a wide glyph) and is unknown.
    fn keep_wide_glyphs_whole(&mut self, row: u16) {
        let half = |cells: &BTreeMap<(u16, u16), PredCell>, col: Option<u16>| {
            col.and_then(|col| cells.get(&(row, col))?.guess.as_ref().map(|g| g.half))
        };
        let split: Vec<u16> = self
            .cells
            .range((row, 0)..=(row, u16::MAX))
            .filter_map(|(&(_, col), cell)| {
                let whole = match cell.guess.as_ref()?.half {
                    Half::Narrow => return None,
                    Half::Wide => half(&self.cells, col.checked_add(1)) == Some(Half::Covered),
                    Half::Covered => half(&self.cells, col.checked_sub(1)) == Some(Half::Wide),
                };
                (!whole).then_some(col)
            })
            .collect();
        for col in split {
            if let Some(cell) = self.cells.get_mut(&(row, col)) {
                cell.guess = None;
            }
        }
    }

    /// The newest epoch the server confirmed echoes. Test-only.
    #[cfg(test)]
    pub const fn confirmed_epoch(&self) -> u64 {
        self.confirmed_epoch
    }
    /// Whether trust carried from a lost connection waits to be given. Test-only.
    #[cfg(test)]
    pub(crate) const fn carries_trust(&self) -> bool {
        self.carried
    }
    /// Type `bytes` as a legacy terminal sends them: each key decoded, then predicted. Test-only.
    #[cfg(test)]
    pub(crate) fn type_bytes(&mut self, bytes: &[u8], screen: &dyn ScreenView) {
        let mut decoder = fux_vt::keys::decode::Decoder::default();
        let mut inputs = Vec::new();
        decoder.bytes(bytes, &mut inputs);
        decoder.timeout(&mut inputs);
        for input in inputs {
            if let fux_vt::keys::decode::Input::Key(key) = input {
                self.new_user_key(key.press, screen);
            }
        }
    }
    /// Confirm the newest epoch, as an echo would. Test-only.
    #[cfg(test)]
    pub(crate) const fn confirm_for_tests(&mut self) {
        self.confirmed_epoch = self.prediction_epoch;
    }
    /// The newest local input frame number sent so far (predictions expire at this + 1).
    pub const fn set_local_frame_sent(&mut self, n: u64) {
        self.local_frame_sent = n;
    }
    /// The server's echo-ack: the newest input frame reflected on screen.
    pub const fn set_local_frame_late_acked(&mut self, n: u64) {
        self.late_acked = n;
    }

    /// The frame a prediction made now expires at: the next input frame. Saturating, so it never
    /// wraps to an expired 0.
    const fn next_frame(&self) -> u64 {
        self.local_frame_sent.saturating_add(1)
    }

    const fn become_tentative(&mut self) {
        // Saturating: wrapping below `confirmed_epoch` would show unconfirmed predictions.
        self.prediction_epoch = self.prediction_epoch.saturating_add(1);
    }

    const fn tentative(&self, epoch: u64) -> bool {
        epoch > self.confirmed_epoch
    }

    /// The predicted cursor's row and column, else the screen's.
    fn cursor_at(&self, screen: &dyn ScreenView) -> (u16, u16) {
        self.cursor
            .as_ref()
            .map_or_else(|| screen.cursor_position(), |c| (c.row, c.col))
    }

    /// Predict the cursor at `(row, col)`, in the current epoch, graded with the next frame; a
    /// guess made in an earlier epoch moves into this one. Every cursor prediction goes through
    /// here.
    fn move_cursor(&mut self, (row, col): (u16, u16)) {
        self.cursor = Some(Guessed {
            expiration_frame: self.next_frame(),
            tentative_epoch: self.prediction_epoch,
            row,
            col,
        });
    }

    /// The cursor to the start of the next row; on the last row it stays (mosh deliberately
    /// predicts no scroll).
    fn newline(&mut self, ctx: &Context<'_>) {
        let (row, _) = self.cursor_at(ctx.screen);
        let next = row.checked_add(1).filter(|&next| next < ctx.size.rows);
        self.move_cursor((next.unwrap_or(row), 0));
    }

    /// The column the line being typed began at, if it began on `row`.
    fn line_start(&self, row: u16) -> Option<u16> {
        match self.line {
            Line::Started(at) if at.row == row => Some(at.col),
            Line::Started(_) | Line::Fresh(_) | Line::Unknown => None,
        }
    }

    /// The first key of a line was typed: it began where the screen shows the cursor, unless the
    /// screen does not show the Enter yet, or a guess for the cursor is pending, when where is
    /// not known.
    fn begin_line(&mut self, screen: &dyn ScreenView) {
        if let Line::Fresh(enter) = self.line {
            self.line = if self.cursor.is_none() && self.late_acked >= enter {
                Line::Started(Confirmed::of(screen))
            } else {
                Line::Unknown
            };
        }
    }

    /// A key not modelled: a new epoch, nothing predicted, and where the line began is no longer
    /// known (the key may have recalled another line, or moved the cursor anywhere).
    const fn unmodelled(&mut self) {
        self.become_tentative();
        self.line = Line::Unknown;
    }

    /// The glyph `(row, col)` shows, predicted or not, or `None` if it is unknown or half of a
    /// wide glyph, where word boundaries cannot be read.
    fn glyph_at(&self, ctx: &Context<'_>, row: u16, col: u16) -> Option<String> {
        self.guess_at(ctx, row, col)
            .filter(|g| g.half == Half::Narrow)
            .map(|g| g.text)
    }

    /// Whether the cell at `(row, col)` holds a character `word` accepts. Blank is no word.
    fn in_word(
        &self,
        ctx: &Context<'_>,
        row: u16,
        col: u16,
        word: fn(char) -> bool,
    ) -> Option<bool> {
        let glyph = self.glyph_at(ctx, row, col)?;
        Some(glyph.chars().next().is_some_and(word))
    }

    /// Predict the grapheme `c` continues or begins, typed at the cursor as a line editor inserts
    /// it (the rest of the row moving right), or as the kernel echoes it.
    ///
    /// A character that continues the glyph before the cursor (an emoji's skin tone, a combining
    /// mark, the rest of an IME's cluster) joins it, as the terminal joins it when it is echoed:
    /// one glyph however many keys typed it, or nothing if joining would change its width. A
    /// glyph reaching the last column, where the terminal may wrap, opens a new epoch.
    fn predict_glyph(&mut self, ctx: &Context<'_>, c: char) {
        if ctx.tty.echo {
            // The kernel echoes it: no need to wait for the program to prove it does.
            self.confirmed_epoch = self.confirmed_epoch.max(self.prediction_epoch);
        }
        let (row, col) = self.cursor_at(ctx.screen);
        if let Some((at, before)) = self.glyph_before(ctx, row, col) {
            if fux_vt::continues_cluster(&before.text, c) {
                let mut joined = before.clone();
                joined.text.push(c);
                if joined.text.width() != before.text.width() {
                    return self.unmodelled();
                }
                self.place(ctx, (row, at), Some(joined), true);
                return self.move_cursor((row, col));
            }
        }
        let text = c.to_string();
        let width = u16::try_from(text.width()).unwrap_or(u16::MAX);
        let cols = ctx.size.cols;
        let Some(end) = col
            .checked_add(width)
            .filter(|&end| width > 0 && end <= cols)
        else {
            return self.unmodelled();
        };
        // Insert mode, as a line editor renders it: shift the tail right, from the right end so
        // each cell reads what moves into it before that is replaced. The rightmost cell takes
        // what a wrapped line brings, unknown; a wide glyph split at the edge is unknown too.
        for i in (end..cols).rev() {
            let from = i.checked_sub(width).filter(|_| i.saturating_add(1) < cols);
            let guess = from.and_then(|from| self.guess_at(ctx, row, from));
            self.place(ctx, (row, i), guess, false);
        }
        // Only the typed glyph borrows its left neighbour's style; the cells it moves keep theirs.
        let attributes = col
            .checked_sub(1)
            .and_then(|left| self.guess_at(ctx, row, left))
            .filter(|left| !left.text.is_empty() || left.half == Half::Covered)
            .map_or_else(Attributes::default, |left| left.attributes);
        let wide = width == 2;
        let glyph = Cell {
            text,
            attributes,
            half: if wide { Half::Wide } else { Half::Narrow },
        };
        self.place(ctx, (row, col), Some(glyph), true);
        if let Some(right) = col.checked_add(1).filter(|_| wide) {
            let covered = Cell {
                text: String::new(),
                attributes,
                half: Half::Covered,
            };
            self.place(ctx, (row, right), Some(covered), true);
        }
        self.keep_wide_glyphs_whole(row);
        if end < cols {
            self.move_cursor((row, end));
        } else {
            // The last column: wrap or overwrite, which is not known; hidden until confirmed.
            self.become_tentative();
            self.newline(ctx);
        }
    }

    /// The glyph left of `(row, col)`, with its column: the cell before it, or the wide glyph
    /// whose right half that is. `None` if it is unknown or blank.
    fn glyph_before(&self, ctx: &Context<'_>, row: u16, col: u16) -> Option<(u16, Cell)> {
        let left = col.checked_sub(1)?;
        let cell = self.guess_at(ctx, row, left)?;
        let (at, cell) = if cell.half == Half::Covered {
            let at = left.checked_sub(1)?;
            (at, self.guess_at(ctx, row, at)?)
        } else {
            (left, cell)
        };
        (!cell.text.is_empty() && cell.half != Half::Covered).then_some((at, cell))
    }

    /// Delete the `n` cells before the cursor as a line editor does: the cursor steps back `n`,
    /// the rest of the row shifts left, wide glyphs whole, and the last cells take what was
    /// off-screen (unknown). Nothing is predicted if a deleted cell is half a wide glyph (a line
    /// editor deletes both halves), or the row's start is in the way.
    fn delete_before(&mut self, ctx: &Context<'_>, n: u16) {
        if n == 0 {
            return;
        }
        let cols = ctx.size.cols;
        let (row, col) = self.cursor_at(ctx.screen);
        let Some(to) = col.checked_sub(n) else {
            return self.unmodelled();
        };
        let wide = (to..col).any(|c| {
            self.guess_at(ctx, row, c)
                .is_none_or(|g| g.half != Half::Narrow)
        });
        if wide {
            return self.unmodelled();
        }
        for i in to..cols {
            // The last two columns take what was off-screen, as in mosh: a wide glyph could
            // straddle the second-to-last.
            let from = i
                .checked_add(n)
                .filter(|&from| from < cols.saturating_sub(1));
            let guess = from.and_then(|from| self.guess_at(ctx, row, from));
            self.place(ctx, (row, i), guess, false);
        }
        self.keep_wide_glyphs_whole(row);
        self.move_cursor((row, to));
    }

    /// Whether Backspace or Left may step back from `(row, col)`: never past where the line began
    /// if that is known, else only over a glyph this line's own guesses typed, so the prompt
    /// before a line whose start is not known (just connected, or after Up or Tab) is never
    /// taken for it.
    fn may_step_back(&self, row: u16, col: u16) -> bool {
        match self.line_start(row) {
            Some(start) => col > start,
            None => col
                .checked_sub(1)
                .and_then(|left| self.cells.get(&(row, left)))
                .is_some_and(|cell| cell.typed),
        }
    }

    /// Backspace: the cell before the cursor deleted, as [`may_step_back`](Self::may_step_back)
    /// allows.
    fn predict_backspace(&mut self, ctx: &Context<'_>) {
        let (row, col) = self.cursor_at(ctx.screen);
        if !self.may_step_back(row, col) {
            return self.unmodelled();
        }
        self.delete_before(ctx, 1);
    }

    /// Left or Right (`right`): the cursor one column over, within the row (Right stops before
    /// the last column), and Left as [`may_step_back`](Self::may_step_back) allows.
    fn predict_arrow(&mut self, ctx: &Context<'_>, right: bool) {
        let (row, col) = self.cursor_at(ctx.screen);
        let to = if right {
            col.checked_add(1).filter(|&next| next < ctx.size.cols)
        } else {
            col.checked_sub(1).filter(|_| self.may_step_back(row, col))
        };
        match to {
            Some(to) => self.move_cursor((row, to)),
            None => self.unmodelled(),
        }
    }

    /// `Ctrl-W` (`word` is not whitespace) or `Alt-Backspace` (`word` is alphanumeric): delete
    /// back over what is not a word, then over the word. Predicted only when the word is bounded
    /// on its left by a cell that is not one, after where the line began if that is known, so a
    /// prompt is never taken for the line.
    fn predict_kill_word(&mut self, ctx: &Context<'_>, word: fn(char) -> bool) {
        if !ctx.editing() {
            return self.unmodelled();
        }
        let (row, col) = self.cursor_at(ctx.screen);
        let start = self.line_start(row);
        let mut at = col;
        let mut seen_word = false;
        loop {
            let Some(prev) = at
                .checked_sub(1)
                .filter(|&p| start.is_none_or(|start| p >= start))
            else {
                // Reached the line's start (or the row's): sure only if where the line began is
                // known, and something was deleted.
                if start.is_some() && at < col {
                    break;
                }
                return self.unmodelled();
            };
            match self.in_word(ctx, row, prev, word) {
                None => return self.unmodelled(),
                Some(true) => seen_word = true,
                Some(false) if seen_word => break,
                Some(false) => {}
            }
            at = prev;
        }
        self.delete_before(ctx, col.saturating_sub(at));
    }

    /// `Ctrl-U`: delete from where the line began to the cursor, if that is known.
    fn predict_kill_line(&mut self, ctx: &Context<'_>) {
        let (row, col) = self.cursor_at(ctx.screen);
        match self.line_start(row).filter(|&start| start <= col) {
            Some(start) if ctx.editing() => self.delete_before(ctx, col.saturating_sub(start)),
            _ => self.unmodelled(),
        }
    }

    /// `Ctrl-A`, Home: the cursor to where the line began, if that is known.
    fn predict_line_start(&mut self, ctx: &Context<'_>) {
        let (row, _) = self.cursor_at(ctx.screen);
        match self.line_start(row) {
            Some(start) if ctx.editing() => self.move_cursor((row, start)),
            _ => self.unmodelled(),
        }
    }

    /// `Ctrl-E`, End: the cursor past the last character of its row, if the line ends on it (the
    /// row is not soft-wrapped into the next) and that is at or after the cursor.
    fn predict_line_end(&mut self, ctx: &Context<'_>) {
        let cols = ctx.size.cols;
        let (row, col) = self.cursor_at(ctx.screen);
        let mut end = 0_u16;
        for c in 0..cols {
            // Typing and deleting leave the last two columns unknown (what an edit pushed off or
            // pulled in): blank unless the line nearly fills the row.
            let edge = c >= cols.saturating_sub(2);
            match self.glyph_at(ctx, row, c) {
                None if edge => {}
                None => return self.unmodelled(),
                Some(g) if !is_blank(&g) => end = c.saturating_add(1),
                Some(_) => {}
            }
        }
        if !ctx.editing() || end < col || end >= cols {
            return self.unmodelled();
        }
        self.move_cursor((row, end));
    }

    /// `Alt-B` (back) or `Alt-F` (`forward`): the cursor over what is not alphanumeric, then over
    /// a word, as readline moves; predicted only when it stops inside the row, and inside the line
    /// if where it began is known.
    fn predict_word_motion(&mut self, ctx: &Context<'_>, forward: bool) {
        if !ctx.editing() {
            return self.unmodelled();
        }
        let cols = ctx.size.cols;
        let (row, col) = self.cursor_at(ctx.screen);
        let start = self.line_start(row);
        let mut at = col;
        let mut seen_word = false;
        loop {
            // The cell to step over: the one before, back; the one at the cursor, forward.
            let next = if forward {
                Some(at).filter(|&a| a < cols.saturating_sub(1))
            } else {
                at.checked_sub(1)
                    .filter(|&p| start.is_none_or(|start| p >= start))
            };
            let Some(cell) = next else {
                if !forward && start.is_some() && seen_word {
                    break;
                }
                return self.unmodelled();
            };
            match self.in_word(ctx, row, cell, char::is_alphanumeric) {
                None => return self.unmodelled(),
                Some(true) => seen_word = true,
                Some(false) if seen_word => break,
                Some(false)
                    if forward && self.glyph_at(ctx, row, cell).is_some_and(|g| is_blank(&g)) =>
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
        self.move_cursor((row, at));
    }

    /// Predict what the edit key `press` does to `screen`, after culling the existing predictions.
    /// The key is read as what it is, whatever the user's terminal sent for it: `Alt-B` from a
    /// kitty-protocol terminal is a legacy one's, and a control is its letter with Ctrl.
    ///
    /// Where the line begins is tracked whatever is predicted: Enter begins a line, whose first
    /// printable key says where.
    pub fn new_user_key(&mut self, press: KeyPress, screen: &dyn ScreenView) {
        self.cull(screen);
        let Modifiers { alt, ctrl, .. } = press.mods;
        let printable = match (press.key, alt, ctrl) {
            (Key::Char(c), false, false) if !c.is_control() => Some(c),
            _ => None,
        };
        if printable.is_some() {
            self.begin_line(screen);
        }
        let ctx = self.context(screen);
        let Some(ctx) = ctx.filter(|_| !self.holding()) else {
            self.become_tentative();
            self.line = match (press.key, alt, ctrl) {
                (Key::Enter, false, false) => Line::Fresh(self.next_frame()),
                _ if printable.is_some() => self.line,
                _ => Line::Unknown,
            };
            return;
        };
        match (press.key, alt, ctrl) {
            (Key::Char(c), false, true) => match c.to_ascii_lowercase() {
                'w' => self.predict_kill_word(&ctx, |c| !c.is_whitespace()),
                'u' => self.predict_kill_line(&ctx),
                'a' => self.predict_line_start(&ctx),
                'e' => self.predict_line_end(&ctx),
                'h' => self.predict_backspace(&ctx),
                'j' | 'm' => self.predict_enter(&ctx),
                _ => self.unmodelled(),
            },
            (Key::Char('b'), true, false) => self.predict_word_motion(&ctx, false),
            (Key::Char('f'), true, false) => self.predict_word_motion(&ctx, true),
            (Key::Backspace, true, false) => {
                self.predict_kill_word(&ctx, char::is_alphanumeric);
            }
            (Key::Char(c), false, false) if !c.is_control() => self.predict_glyph(&ctx, c),
            (Key::Backspace, false, false) => self.predict_backspace(&ctx),
            (Key::Enter, false, false) => self.predict_enter(&ctx),
            // The kernel echoes an arrow as `^[[D`: only a line editor moves the cursor.
            (Key::Arrow(Direction::Right), false, false) if ctx.editing() => {
                self.predict_arrow(&ctx, true);
            }
            (Key::Arrow(Direction::Left), false, false) if ctx.editing() => {
                self.predict_arrow(&ctx, false);
            }
            (Key::Home, false, false) => self.predict_line_start(&ctx),
            (Key::End, false, false) => self.predict_line_end(&ctx),
            // Anything else is not predicted.
            _ => self.unmodelled(),
        }
    }

    /// Predict nothing for what is typed now, nor after, until the server has reflected it: for a
    /// key whose echo is in doubt. The client may not yet know the PTY's modes as they are now (a
    /// program that printed a prompt may turn echo off a moment after), and a key typed at a
    /// password prompt must never be shown. Predictions already made stand.
    pub const fn hold(&mut self) {
        self.held_through = Some(self.next_frame());
        self.become_tentative();
    }

    /// Whether a held key is not yet reflected on the screen.
    const fn holding(&mut self) -> bool {
        match self.held_through {
            Some(held) if self.late_acked < held => true,
            Some(_) => {
                self.held_through = None;
                false
            }
            None => false,
        }
    }

    /// Input the predictor does not model reached the program (a mouse event, a paste): what it
    /// shows next is unknown.
    pub fn new_user_other(&mut self, screen: &dyn ScreenView) {
        self.cull(screen);
        self.unmodelled();
    }

    /// Enter: a scroll cannot be predicted cleanly, so a new epoch, the cursor to the next row,
    /// and a line begun.
    fn predict_enter(&mut self, ctx: &Context<'_>) {
        self.become_tentative();
        self.newline(ctx);
        self.line = Line::Fresh(self.next_frame());
    }

    /// Grade the predictions against `screen`, a frame's: confirmed ones go (the screen shows
    /// them), a wrong one takes its epoch with it, or every prediction if its epoch was shown.
    pub fn cull(&mut self, screen: &dyn ScreenView) {
        let size = screen.size();
        // Reset predictions on a genuine resize, but not on the very first cull.
        if self
            .last_size
            .replace(size)
            .is_some_and(|prev| prev != size)
        {
            return self.reset();
        }
        let late = self.late_acked;
        let mut to_remove: Vec<(u16, u16)> = Vec::new();
        let mut kill_epochs: BTreeSet<u64> = BTreeSet::new();
        let mut max_confirm = self.confirmed_epoch;
        let mut kill_all = false;
        // As mosh does, a confirmed cell's style recolours the pending typed glyphs right of it,
        // so they don't show a guessed style until their own frame: `(row, from_col, style)`,
        // applied after this pass.
        let mut restyle: Vec<(u16, u16, Attributes)> = Vec::new();

        for (&(row, col), cell) in &self.cells {
            match cell_validity(cell, screen, row, col, late) {
                Validity::Pending => {}
                Validity::Correct => {
                    max_confirm = max_confirm.max(cell.tentative_epoch);
                    if let Some(actual) = screen.cell(row, col) {
                        restyle.push((row, col, actual.attributes()));
                    }
                    to_remove.push((row, col));
                }
                Validity::CorrectNoCredit => to_remove.push((row, col)),
                Validity::IncorrectOrExpired if self.tentative(cell.tentative_epoch) => {
                    kill_epochs.insert(cell.tentative_epoch);
                    to_remove.push((row, col));
                }
                // A shown guess was wrong: everything goes.
                Validity::IncorrectOrExpired => {
                    kill_all = true;
                    break;
                }
            }
        }
        if kill_all {
            return self.reset();
        }
        self.confirmed_epoch = max_confirm;
        for k in &to_remove {
            self.cells.remove(k);
        }
        // In order, so the rightmost confirmed cell's style wins, as in mosh.
        for &(row, from_col, attributes) in &restyle {
            for (_, cell) in self.cells.range_mut((row, from_col)..=(row, u16::MAX)) {
                if let (true, Some(guess)) = (cell.typed, cell.guess.as_mut()) {
                    guess.attributes = attributes;
                }
            }
        }
        if !kill_epochs.is_empty() {
            self.cells
                .retain(|_, c| !kill_epochs.contains(&c.tentative_epoch));
            self.discard_line();
            self.become_tentative();
            // As mosh's kill_epoch: a new cursor at the real position, in the new (hidden) epoch,
            // so the killed epoch's cursor is not drawn.
            self.move_cursor(screen.cursor_position());
        }

        if let Some(c) = &self.cursor {
            match cursor_validity(c, screen, late) {
                Validity::IncorrectOrExpired => self.reset(),
                Validity::Pending => {}
                Validity::Correct | Validity::CorrectNoCredit => self.cursor = None,
            }
        }
    }

    /// What to draw now: the predictions in confirmed epochs, unless at a password prompt.
    pub fn overlay(&self) -> Overlay {
        if self.tty.is_some_and(TtyModes::password) {
            return Overlay::default();
        }
        let cells = self
            .cells
            .iter()
            .filter(|(_, cell)| !self.tentative(cell.tentative_epoch))
            .filter_map(|(&at, cell)| Some((at, cell.guess.clone()?)))
            .collect();
        let cursor = self
            .cursor
            .as_ref()
            .filter(|c| !self.tentative(c.tentative_epoch))
            .map(|c| (c.row, c.col));
        Overlay { cells, cursor }
    }

    /// Where the line began is no longer sure once the guesses made on it are discarded; a line
    /// only begun (Enter typed) still begins at the next confirmed cursor.
    fn discard_line(&mut self) {
        if matches!(self.line, Line::Started(_)) {
            self.line = Line::Unknown;
        }
    }

    /// Drop all predictions and open a fresh epoch (after a mispredict or a resize).
    pub fn reset(&mut self) {
        self.cells.clear();
        self.cursor = None;
        self.discard_line();
        self.become_tentative();
    }
}

fn is_blank(s: &str) -> bool {
    s.is_empty() || s == " "
}

fn cell_validity(
    cell: &PredCell,
    screen: &dyn ScreenView,
    row: u16,
    col: u16,
    late_acked: u64,
) -> Validity {
    let Some(actual) = screen.cell(row, col) else {
        return Validity::IncorrectOrExpired;
    };
    if late_acked < cell.expiration_frame {
        return Validity::Pending;
    }
    let Some(guess) = &cell.guess else {
        // We never predicted a concrete glyph here, so it can never *confirm* an epoch.
        return Validity::CorrectNoCredit;
    };
    if guess.half == Half::Covered {
        // A wide glyph's right half says nothing of its own: right when the server shows one here,
        // never credit (its glyph, to the left, is graded).
        return if actual.is_wide_continuation() {
            Validity::CorrectNoCredit
        } else {
            Validity::IncorrectOrExpired
        };
    }
    if is_blank(&guess.text) {
        return Validity::CorrectNoCredit; // too easy to falsely match
    }
    if actual.contents() != guess.text {
        Validity::IncorrectOrExpired
    } else if cell.original == guess.text {
        Validity::CorrectNoCredit // it already looked like this earlier; no credit
    } else {
        Validity::Correct
    }
}

fn cursor_validity(cur: &Guessed, screen: &dyn ScreenView, late_acked: u64) -> Validity {
    let Size { rows, cols } = screen.size();
    if cur.row >= rows || cur.col >= cols {
        return Validity::IncorrectOrExpired;
    }
    if late_acked < cur.expiration_frame {
        Validity::Pending
    } else if screen.cursor_position() == (cur.row, cur.col) {
        Validity::Correct
    } else {
        Validity::IncorrectOrExpired
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use fux_vt::{Color, Screen};

    impl ScreenView for Screen {
        fn size(&self) -> Size {
            let (rows, cols) = Self::size(self).into();
            Size { rows, cols }
        }
        fn cursor_position(&self) -> (u16, u16) {
            Self::cursor_position(self)
        }
        fn cell(&self, row: u16, col: u16) -> Option<CellRef<'_>> {
            Self::cell(self, row, col)
        }
        fn alternate(&self) -> bool {
            self.mode(fux_vt::Mode::AlternateScreen)
        }
    }

    /// The PTY's modes under a line editor (readline): it echoes for itself, a key at a time.
    const EDITOR: TtyModes = TtyModes {
        echo: false,
        line: false,
    };

    /// A predictor that has seen nothing but the PTY's modes, a line editor's.
    fn engine() -> PredictionEngine {
        let mut e = PredictionEngine::default();
        e.set_tty(Some(EDITOR));
        e
    }

    fn screen_of(bytes: &[u8]) -> Screen {
        sized_screen_of(24, 80, bytes)
    }

    /// A screen of `rows`×`cols` showing `bytes`.
    fn sized_screen_of(rows: u16, cols: u16, bytes: &[u8]) -> Screen {
        let mut p = fux_vt::Parser::new(fux_vt::Size::new(rows, cols).expect("nonzero size"), 0)
            .expect("parser");
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
        fn cell(&self, row: u16, col: u16) -> Option<CellRef<'_>> {
            // Leak-free static strs for the tiny alphabet the test uses.
            let ch = *self.rows.get(row as usize)?.get(col as usize)?;
            let contents: &'static str = match ch {
                ' ' => "",
                'x' => "x",
                'y' => "y",
                _ => "?",
            };
            Some(CellRef::new(contents, false, Attributes::default()))
        }
        fn alternate(&self) -> bool {
            false
        }
    }

    /// The glyph predicted shown at `(row, col)`.
    fn shown_at(e: &PredictionEngine, row: u16, col: u16) -> Option<String> {
        e.overlay().cell(row, col).map(|c| c.text().to_owned())
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
        let mut e = engine();
        e.type_bytes(b"x", &blank);
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
        e.type_bytes(b"y", &echoed);
        assert_eq!(
            shown_at(&e, 0, 1).as_deref(),
            Some("y"),
            "typing after confirmation is visible over the fake view"
        );
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

        /// Whatever keys arbitrary bytes decode to, predicting them over a fake view or an
        /// emulator's screen never panics.
        #[test]
        fn prop_predicting_any_keys_is_panic_free(
            bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..256),
        ) {
            let fake = FakeView { rows: vec![vec![' '; 80]; 24], cursor: (0, 0) };
            let mut pf = engine();
            pf.type_bytes(&bytes, &fake);
            let mut pe = engine();
            pe.type_bytes(&bytes, &screen_of(b"ready prompt $ "));
            let _ = pe.overlay();
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
            // Everything shown: the check is on what the overlay holds, not on when it confirms.
            let mut e = PredictionEngine {
                confirmed_epoch: u64::MAX,
                ..engine()
            };
            for key in bytes {
                e.type_bytes(key, &screen);
                let ov = e.overlay();
                for ((row, col), cell) in ov.cells() {
                    let left = col.checked_sub(1).and_then(|left| ov.cell(row, left));
                    let right = col.checked_add(1).and_then(|right| ov.cell(row, right));
                    if cell.covered() {
                        proptest::prop_assert!(
                            left.is_some_and(|l| !l.covered() && l.text().width() == 2),
                            "a covered cell at {col} follows no wide glyph"
                        );
                    } else if cell.text().width() == 2 {
                        proptest::prop_assert!(
                            right.is_some_and(Cell::covered),
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
        let mut e = engine();
        let blank = screen_of(b"");
        e.type_bytes(b"x", &blank);
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
    fn no_echo_keeps_secret_hidden_and_cleans_up() {
        // P0 (security): a secret typed before any server confirmation is never drawn, and one
        // the server never echoes (a password prompt) is culled away.
        let mut e = engine();
        e.type_bytes(b"hunter2", &screen_of(b""));
        assert!(e.overlay().is_empty(), "non-echoed input is never shown");
        e.set_local_frame_late_acked(1);
        e.cull(&screen_of(b""));
        assert!(
            e.overlay().is_empty(),
            "non-echoed input must not leave a predicted glyph"
        );
    }

    /// What is predicted at `(0, col)`: the glyph, `U` for unknown, `>` for a covered cell.
    fn predicted_at(e: &PredictionEngine, col: u16) -> Option<String> {
        e.cells.get(&(0, col)).map(|c| match &c.guess {
            None => "U".to_owned(),
            Some(g) if g.covered() => ">".to_owned(),
            Some(g) => g.text.clone(),
        })
    }

    /// Assert the glyphs predicted on row 0 from column `from`, as [`predicted_at`] names them.
    fn predicted_row(e: &PredictionEngine, from: u16, glyphs: &[&str]) {
        let row: Vec<_> = (from..)
            .zip(glyphs)
            .map(|(col, _)| predicted_at(e, col))
            .collect();
        let expected: Vec<_> = glyphs.iter().map(|g| Some((*g).to_owned())).collect();
        assert_eq!(row, expected);
    }

    #[test]
    fn insert_mode_shifts_the_row_right_wide_glyphs_whole() {
        // Typing 'X' INSERTS before the cursor, shifting the tail right, not overwriting it.
        // (Inspect predicted cells directly; the epoch gate hides them from overlay() until
        // confirmed, but the shift populates cells.)
        for (screen, from, glyphs) in [
            ("ab\x1b[1;2H", 1, &["X", "b"][..]),
            ("a本b\x1b[1;1H", 0, &["X", "a", "本", ">", "b"]),
        ] {
            let mut e = engine();
            e.type_bytes(b"X", &screen_of(screen.as_bytes()));
            predicted_row(&e, from, glyphs);
        }
    }

    #[test]
    fn insert_mode_backspace_shifts_left_with_unknown_right_edge() {
        // Screen "abc" cursor on 'c' (col 2). Backspace deletes 'b': 'c' shifts left to col 1,
        // and the last TWO columns become unknown (content scrolled in from off-screen; mosh marks
        // the cell unknown when `i + 2 >= width`, so both edge columns, not just the last one).
        let mut e = engine();
        e.line = Line::Started(Confirmed { row: 0, col: 0 });
        e.type_bytes(&[0x7f], &screen_of(b"abc\x1b[1;3H"));
        predicted_row(&e, 1, &["c"]);
        // A blank moved in, then the two unknown edge columns.
        predicted_row(&e, 77, &["", "U", "U"]);
    }

    #[test]
    fn insert_mode_backspace_does_not_overflow_at_max_width() {
        // The unknown-column guard must be overflow-safe on a peer-controlled width: at
        // cols == u16::MAX a naive `i + 2` overflows u16. The predicted cursor is near the right
        // edge so the backspace runs its shift out to the final column.
        let p = fux_vt::Parser::new(fux_vt::Size::new(1, u16::MAX).expect("nonzero size"), 0)
            .expect("1-row parser");
        let mut e = engine();
        e.move_cursor((0, u16::MAX - 1));
        e.line = Line::Started(Confirmed { row: 0, col: 0 });
        e.type_bytes(&[0x7f], p.screen());
        predicted_row(&e, u16::MAX - 2, &["U", "U"]);
    }

    #[test]
    fn correct_grade_restyles_the_pending_typed_glyphs_right_of_it() {
        // mosh "match rest of row to the actual renditions": when a typed glyph confirms in a
        // style, the still-pending typed glyphs to its right take that whole style (so they don't
        // flash a guessed one before their own frame confirms).
        let (mut e, echoed) = confirm_first_keystroke();
        // 'b' on frame 2 (will be confirmed), 'c' on frame 3 (stays pending).
        e.set_local_frame_sent(1);
        e.type_bytes(b"b", &echoed);
        e.set_local_frame_sent(2);
        e.type_bytes(b"c", &echoed);
        let style = |e: &PredictionEngine| e.overlay().cell(0, 2).map(Cell::attributes);
        assert_eq!(style(&e), Some(Attributes::default()), "guessed");
        // The server echoes 'b' bold red and acks frame 2.
        let colored = screen_of(b"x\x1b[1;31mb");
        e.set_local_frame_late_acked(2);
        e.cull(&colored);
        let confirmed = colored.cell(0, 1).map(|c| c.attributes());
        assert!(confirmed.is_some_and(|a| a.bold() && a.foreground() == Color::Idx(1)));
        assert_eq!(style(&e), confirmed, "'c' takes 'b''s whole style");
    }

    /// The cells a line editor moves keep every attribute they have, and only the typed glyph
    /// borrows its left neighbour's, hidden included, as the echo will show them.
    #[test]
    fn predicted_cells_keep_their_style() {
        let screen = screen_of(b"\x1b[8ma\x1b[m\x1b[1;4;7;31mbc\x1b[m\x1b[1;2H");
        let (mut e, _) = confirm_first_keystroke();
        e.set_local_frame_sent(1);
        e.type_bytes(b"X", &screen);
        let at = |col| {
            e.overlay()
                .cell(0, col)
                .map(|c| (c.text().to_owned(), c.attributes()))
        };
        let real = |col| screen.cell(0, col).map(|c| c.attributes());
        assert_eq!(at(1).map(|(t, _)| t).as_deref(), Some("X"));
        assert_eq!(
            at(1).map(|(_, a)| a),
            real(0),
            "the typed glyph: its neighbour's, hidden"
        );
        assert!(at(1).is_some_and(|(_, a)| a.hidden()));
        for (col, from) in [(2, 1), (3, 2)] {
            assert_eq!(
                at(col).map(|(_, a)| a),
                real(from),
                "column {col} moved whole"
            );
        }
        assert!(at(2).is_some_and(|(_, a)| a.bold() && a.inverse() && a.underline()));
    }

    #[test]
    fn killed_epoch_reseeds_cursor_off_stale_position() {
        // A tentative-epoch mispredict kills that epoch. mosh's kill_epoch re-seeds the cursor at
        // the real screen position so a *confirmed-but-stale* predicted cursor — one that would
        // otherwise keep being drawn at a position the killed predictions had moved it to — is
        // displaced. Built from raw state to isolate exactly that condition.
        let mut e = PredictionEngine {
            confirmed_epoch: 1,
            prediction_epoch: 2,
            ..engine()
        };
        e.set_local_frame_sent(5);
        e.set_local_frame_late_acked(5);
        // A CONFIRMED (epoch 1 <= confirmed 1) cursor at a stale column, still Pending (expiration
        // far ahead of late_acked) so the validation pass won't resolve it — it would keep drawing.
        e.cursor = Some(Guessed {
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
                guess: Some(Cell {
                    text: "Q".to_owned(),
                    attributes: Attributes::default(),
                    half: Half::Narrow,
                }),
                original: String::new(),
                typed: true,
            },
        );
        let blank = screen_of(b"");
        assert_eq!(e.overlay().cursor(), Some((0, 9)), "drawn before the kill");
        // The frame has no 'Q' at (0,3) -> epoch 2 is killed; the real cursor is at (0,0).
        e.cull(&blank);
        assert!(
            e.overlay().cursor().is_none(),
            "after kill_epoch the stale predicted cursor is displaced; the real cursor shows through"
        );
        let c = e.cursor.as_ref().expect("kill_epoch re-seeds a cursor");
        assert_eq!((c.row, c.col), (0, 0), "at the real screen position");
    }

    #[test]
    fn left_arrow_predicts_cursor_and_leaves_no_glyph() {
        // After confirming a keystroke (cursor at (0,1)), a left arrow, in either cursor mode,
        // predicts the cursor one column left and leaves no glyph from its escape bytes.
        for arrow in [&b"\x1b[D"[..], b"\x1bOD"] {
            let (mut e, echoed) = confirm_first_keystroke();
            e.set_local_frame_sent(1);
            e.line = Line::Started(Confirmed { row: 0, col: 0 });
            e.type_bytes(arrow, &echoed);
            let ov = e.overlay();
            assert_eq!(ov.cursor(), Some((0, 0)), "{arrow:?}");
            assert!(ov.cell(0, 0).is_none() && ov.cell(0, 1).is_none());
        }
    }

    #[test]
    fn double_width_grapheme_predicted_and_advances_cursor_by_two() {
        // A CJK character is double-width: its multi-byte UTF-8 arrives one byte at a time and is
        // reassembled into a single predicted glyph, with the cursor stepping forward two cells
        // (and no stray glyph in the continuation cell).
        let (mut e, echoed) = confirm_first_keystroke();
        e.set_local_frame_sent(1);
        e.type_bytes("世".as_bytes(), &echoed);
        let ov = e.overlay();
        assert_eq!(ov.cell(0, 1).map(Cell::text), Some("世"));
        assert!(ov
            .cell(0, 2)
            .is_some_and(|c| c.covered() && c.text().is_empty()));
        assert_eq!(ov.cursor(), Some((0, 3)));
    }

    /// An emoji with a skin tone, typed in one keystroke or two (an IME commits it as two
    /// characters), is one glyph, as the terminal joins it when it is echoed.
    #[test]
    fn a_grapheme_typed_in_pieces_is_one_glyph() {
        let (mut e, echoed) = confirm_first_keystroke();
        e.set_local_frame_sent(1);
        e.type_bytes("\u{1f44d}\u{1f3fd}a".as_bytes(), &echoed);
        let ov = e.overlay();
        assert_eq!(ov.cell(0, 1).map(Cell::text), Some("\u{1f44d}\u{1f3fd}"));
        assert!(ov.cell(0, 2).is_some_and(Cell::covered));
        assert_eq!(ov.cell(0, 3).map(Cell::text), Some("a"));
        assert_eq!(ov.cursor(), Some((0, 4)));
        // A joiner that would make the glyph wider is not guessed at all.
        let (mut e, echoed) = confirm_first_keystroke();
        e.set_local_frame_sent(1);
        let epoch = e.prediction_epoch;
        e.type_bytes("\u{2764}\u{fe0f}".as_bytes(), &echoed);
        assert!(
            e.prediction_epoch > epoch,
            "the heart's widening opened a new epoch"
        );
        assert!(shown_at(&e, 0, 1).is_none_or(|g| g == "\u{2764}"));
    }

    #[test]
    fn a_wide_glyph_split_by_a_shift_is_unknown() {
        // Pushed to the edge, its right half would leave the screen.
        let mut e = engine();
        e.type_bytes(b"X", &sized_screen_of(2, 6, "abc本\x1b[1;1H".as_bytes()));
        predicted_row(&e, 4, &["U", "U"]);
        // Typed inside one, its halves part: the moved right half is unknown.
        let mut e = engine();
        e.type_bytes(b"a", &screen_of("本x\x1b[1;2H".as_bytes()));
        predicted_row(&e, 1, &["a", "U"]);
        // Deleting before one moves it left, whole.
        let mut e = engine();
        e.line = Line::Started(Confirmed { row: 0, col: 0 });
        e.type_bytes(&[0x7f], &screen_of("ab本c\x1b[1;3H".as_bytes()));
        predicted_row(&e, 1, &["本", ">", "c"]);
    }

    #[test]
    fn a_wide_glyph_typed_inside_another_leaves_neither_half_of_that_one() {
        let (mut e, echoed) = confirm_first_keystroke();
        e.set_local_frame_sent(1);
        e.type_bytes("日".as_bytes(), &echoed);
        e.move_cursor((0, 2));
        e.type_bytes("本".as_bytes(), &echoed);
        predicted_row(&e, 1, &["U", "本", ">", "U"]);
    }

    #[test]
    fn backspace_over_a_wide_glyph_is_not_predicted() {
        // A line editor deletes both halves: not modelled, so a new epoch and nothing predicted.
        let (mut e, _) = confirm_first_keystroke();
        e.set_local_frame_sent(1);
        let epoch = e.prediction_epoch;
        e.type_bytes(&[0x7f], &screen_of("x本".as_bytes()));
        assert!(e.cells.is_empty(), "nothing predicted");
        assert!(e.prediction_epoch > epoch, "a new epoch");
        assert!(e.overlay().is_empty());
    }

    #[test]
    fn a_covered_cell_is_graded_against_a_right_half_and_confirms_nothing() {
        let covered = PredCell {
            expiration_frame: 1,
            tentative_epoch: 1,
            guess: Some(Cell {
                text: String::new(),
                attributes: Attributes::default(),
                half: Half::Covered,
            }),
            original: String::new(),
            typed: true,
        };
        let wide = screen_of("x本".as_bytes());
        let narrow = screen_of(b"xab");
        assert!(cell_validity(&covered, &wide, 0, 2, 1) == Validity::CorrectNoCredit);
        assert!(cell_validity(&covered, &narrow, 0, 2, 1) == Validity::IncorrectOrExpired);
        assert!(cell_validity(&covered, &narrow, 0, 2, 0) == Validity::Pending);
    }

    #[test]
    fn prediction_reassembles_multibyte_utf8_no_stray_byte() {
        // mosh prediction-unicode regression: typing "glück" must predict 'ü', and "faĩl" 'ĩ' —
        // NOT the low byte of the code point. koh reassembles the whole UTF-8 grapheme before
        // predicting, so the predicted glyph is always the real character.
        for (word, accent) in [("glück", "ü"), ("faĩl", "ĩ")] {
            let (mut e, echoed) = confirm_first_keystroke();
            e.set_local_frame_sent(1);
            e.type_bytes(word.as_bytes(), &echoed);
            assert_eq!(shown_at(&e, 0, 3).as_deref(), Some(accent), "{word}");
            assert!(
                e.overlay().cells().all(|(_, c)| c.text() != ")"),
                "{word}: ĩ must not collapse to its low byte ')'"
            );
        }
    }

    /// A predictor trusted at a line editor, on `bytes`' screen.
    fn editor_on(bytes: &[u8]) -> (PredictionEngine, Screen) {
        let mut e = PredictionEngine::default();
        let screen = screen_of(bytes);
        e.carried = true;
        e.set_tty(Some(EDITOR));
        e.cull(&screen);
        (e, screen)
    }

    /// Type `keys` into `e` over `screen`, as one input frame.
    fn type_keys(e: &mut PredictionEngine, screen: &Screen, keys: &[u8]) {
        e.set_local_frame_sent(1);
        e.type_bytes(keys, screen);
    }

    /// Row 0 as shown: the overlay over the screen, trailing blanks trimmed; and the cursor's
    /// column as predicted.
    fn shown_row(e: &PredictionEngine, screen: &Screen) -> (String, Option<u16>) {
        let ov = e.overlay();
        let text: String = (0..80)
            .map(|col| match ov.cell(0, col) {
                Some(cell) => cell.text().to_owned(),
                None => screen
                    .cell(0, col)
                    .map(|c| c.contents().to_owned())
                    .unwrap_or_default(),
            })
            .map(|g| if g.is_empty() { " ".to_owned() } else { g })
            .collect();
        (text.trim_end().to_owned(), ov.cursor().map(|(_, c)| c))
    }

    /// Ctrl-W deletes the word before the cursor, and never the prompt's; Alt-Backspace deletes
    /// back to punctuation; a CSI with parameters (Delete, Ctrl-Right) is read whole and draws
    /// no '~' or 'C'.
    #[test]
    fn line_edits_delete_as_the_line_editor_does() {
        for (line, keys, text, col) in [
            (
                &b"$ git commit -m msg"[..],
                &b"\x17"[..],
                "$ git commit -m",
                Some(16),
            ),
            (
                b"$ git commit -m msg",
                b"\x17\x17",
                "$ git commit",
                Some(13),
            ),
            (b"$ cd /usr/lib", b"\x1b\x7f", "$ cd /usr/", Some(10)),
            (b"$ ab", b"\x1b[3~\x1b[1;5C", "$ ab", None),
        ] {
            let (mut e, screen) = editor_on(line);
            type_keys(&mut e, &screen, keys);
            assert_eq!(shown_row(&e, &screen), (text.to_owned(), col), "{keys:?}");
        }
        // An empty line: the word left of the cursor is the prompt's, which is not the line's.
        let (mut e, screen) = editor_on(b"$ ");
        type_keys(&mut e, &screen, &[0x17]);
        assert!(e.overlay().is_empty(), "nothing predicted");
    }

    #[test]
    fn ctrl_u_and_ctrl_a_go_to_where_the_line_began_only_when_it_is_known() {
        let (mut e, screen) = editor_on(b"$ ls -l");
        type_keys(&mut e, &screen, &[0x15]);
        assert!(e.overlay().is_empty(), "where the line began is not known");
        // Typed after Enter, the line's start is known.
        let (mut e, screen) = editor_on(b"$ ");
        e.line = Line::Fresh(0);
        type_keys(&mut e, &screen, b"echo hi");
        assert_eq!(shown_row(&e, &screen), ("$ echo hi".to_owned(), Some(9)));
        type_keys(&mut e, &screen, &[0x01]);
        assert_eq!(shown_row(&e, &screen).1, Some(2), "Ctrl-A");
        type_keys(&mut e, &screen, &[0x05]);
        assert_eq!(shown_row(&e, &screen).1, Some(9), "Ctrl-E");
        type_keys(&mut e, &screen, &[0x15]);
        assert_eq!(shown_row(&e, &screen), ("$".to_owned(), Some(2)), "Ctrl-U");
    }

    /// The line begins where a frame shows the cursor, never where a guess put it: after Enter
    /// the prompt is drawn where the guess put the cursor, so a key typed before the frame that
    /// shows it leaves the line's start unknown, and Ctrl-A is not predicted into the prompt.
    #[test]
    fn the_line_begins_at_a_confirmed_cursor_not_a_guessed_one() {
        let (mut e, screen) = editor_on(b"$ ls");
        type_keys(&mut e, &screen, b"\r");
        type_keys(&mut e, &screen, b"x");
        type_keys(&mut e, &screen, &[0x01]);
        assert_eq!(
            e.line,
            Line::Unknown,
            "a guess was pending at the first key"
        );
        // The frame shows the new prompt; the line begins after it, where the screen says.
        let (mut e, screen) = editor_on(b"$ ls");
        type_keys(&mut e, &screen, b"\r");
        let prompt = screen_of(b"$ ls\r\nfile\r\n$ ");
        e.set_local_frame_late_acked(2);
        e.cull(&prompt);
        e.set_local_frame_sent(2);
        e.type_bytes(b"ab\x01", &prompt);
        assert_eq!(e.line, Line::Started(Confirmed { row: 2, col: 2 }));
        // A discarded guess takes the line's start with it.
        e.reset();
        assert_eq!(e.line, Line::Unknown);
    }

    #[test]
    fn backspace_and_left_never_go_past_where_the_line_began() {
        let (mut e, screen) = editor_on(b"$ ");
        e.line = Line::Started(Confirmed { row: 0, col: 2 });
        for key in [&b"\x7f"[..], b"\x1b[D", b"\x08"] {
            let epoch = e.prediction_epoch;
            type_keys(&mut e, &screen, key);
            assert!(e.overlay().is_empty(), "{key:?}");
            assert!(e.prediction_epoch > epoch, "{key:?} opened a new epoch");
            e.line = Line::Started(Confirmed { row: 0, col: 2 });
            // Where the line began is not known: only over what its own guesses typed.
            let (mut e, screen) = editor_on(b"$ ");
            type_keys(&mut e, &screen, key);
            assert!(e.overlay().is_empty(), "{key:?} into the prompt");
            let (mut e, screen) = editor_on(b"$ ");
            type_keys(&mut e, &screen, b"ab");
            for col in [3, 2, 2] {
                type_keys(&mut e, &screen, key);
                assert_eq!(shown_row(&e, &screen).1, Some(col), "{key:?}");
            }
        }
    }

    #[test]
    fn home_end_and_word_motion_move_the_cursor_only() {
        let (mut e, screen) = editor_on(b"$ make test\x1b[2D");
        for (keys, col, what) in [
            (&b"\x1b[F"[..], 11, "End"),
            (b"\x1bb", 7, "Alt-B: the start of test"),
            (b"\x1bb", 2, "Alt-B: the start of make"),
            (b"\x1bf", 6, "Alt-F: the end of make"),
            // The line's start unknown: not predicted; the cursor stays where it was.
            (b"\x1b[1~", 6, "Home"),
        ] {
            type_keys(&mut e, &screen, keys);
            let shown = shown_row(&e, &screen);
            assert_eq!(shown, ("$ make test".to_owned(), Some(col)), "{what}");
        }
    }

    #[test]
    fn a_password_prompt_shows_nothing_typed_even_after_trust() {
        let (mut e, screen) = editor_on(b"$ ");
        type_keys(&mut e, &screen, b"sudo");
        assert!(!e.overlay().is_empty(), "trusted at the shell");
        // sudo turns echo off and reads a line: whatever was trusted, nothing shows.
        let prompt = screen_of(b"$ sudo\r\n[sudo] password for me: ");
        let password = TtyModes {
            echo: false,
            line: true,
        };
        e.set_tty(Some(password));
        e.cull(&prompt);
        type_keys(&mut e, &prompt, b"hunter2");
        assert!(e.overlay().is_empty());
        assert!(e.cells.is_empty(), "nothing even kept");
        // Carried trust is not given at one either.
        let mut fresh = PredictionEngine {
            carried: true,
            ..PredictionEngine::default()
        };
        fresh.set_tty(Some(password));
        type_keys(&mut fresh, &prompt, b"hunter2");
        assert!(fresh.overlay().is_empty());
    }

    /// Modes not known are not a password prompt's, nor anything else's: carried trust waits
    /// for known ones.
    #[test]
    fn unknown_modes_give_no_carried_trust() {
        let mut e = PredictionEngine {
            carried: true,
            ..PredictionEngine::default()
        };
        e.set_tty(None);
        assert!(e.carries_trust(), "still carried");
        e.set_tty(Some(EDITOR));
        assert!(!e.carries_trust(), "given");
        assert_eq!(e.confirmed_epoch, e.prediction_epoch);
    }

    #[test]
    fn kernel_echo_is_trusted_from_the_first_key() {
        let mut e = PredictionEngine::default();
        let screen = screen_of(b"");
        e.set_tty(Some(TtyModes {
            echo: true,
            line: true,
        }));
        type_keys(&mut e, &screen, b"hi");
        assert_eq!(shown_row(&e, &screen), ("hi".to_owned(), Some(2)));
        // Without the modes known, nothing is predicted at all.
        let mut e = PredictionEngine::default();
        type_keys(&mut e, &screen, b"hi");
        assert!(e.overlay().is_empty() && e.cells.is_empty());
    }

    /// tmux's and screen's prefix (Ctrl-A) and vim's keys are not a line editor's: on the
    /// alternate screen nothing is predicted, however trusted the session.
    #[test]
    fn nothing_is_predicted_on_the_alternate_screen() {
        let (mut e, _) = editor_on(b"$ ");
        let tmux = screen_of(b"\x1b[?1049h$ ls");
        type_keys(&mut e, &tmux, b"\x01c");
        assert!(e.overlay().is_empty() && e.cells.is_empty());
    }
}
