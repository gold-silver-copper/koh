//! Local-echo prediction: the client guesses what each keystroke does to the screen and shows it at
//! once, then confirms or corrects it when the server's frame arrives.
//!
//! Guesses are grouped in epochs, confirmed by the server's echo-ack, so input a program does not
//! echo (a password) is never shown. Only edit keys reach it, and only in a `Context`: on the
//! primary screen, with the PTY's modes known and not a password prompt, so a full-screen program
//! (or tmux's and screen's prefix keys) is never taken for a line editor. It predicts only what
//! cannot be wrong: a printable grapheme typed onto blank cells (wide ones included, and one glyph
//! for a grapheme however many keys typed it), Backspace at a line's end, Enter, Left and Right.
//! No other cell of the row is moved, so a right-side prompt stays where it is. Any other key opens
//! a new epoch and waits for the server. A typed glyph takes its left neighbour's style. A wrong
//! guess is reconciled away, never left on screen. The renderer draws an [`Overlay`].

use std::collections::{BTreeMap, BTreeSet};

use fux_vt::keys::{Direction, Key, KeyPress, Modifiers};
use fux_vt::{Attributes, CellRef, Mode, Screen};
use unicode_width::UnicodeWidthStr;

use crate::terminal::TtyModes;

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

    /// Its glyph: empty for a blank or a covered cell.
    pub fn text(&self) -> &str {
        &self.text
    }

    pub const fn attributes(&self) -> Attributes {
        self.attributes
    }

    pub fn covered(&self) -> bool {
        self.half == Half::Covered
    }

    fn blank(&self) -> bool {
        self.half == Half::Narrow && is_blank(&self.text)
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
    /// Every predicted cell, in `(row, col)` order.
    pub fn cells(&self) -> impl Iterator<Item = ((u16, u16), &Cell)> + '_ {
        self.cells.iter().map(|(&at, cell)| (at, cell))
    }
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
    /// The line began at `(row, col)`, where a frame showed the cursor: Backspace and Left never
    /// go past it.
    Started(u16, u16),
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
    screen: &'a Screen,
    tty: TtyModes,
    rows: u16,
    cols: u16,
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
    last_size: Option<fux_vt::Size>,
    /// How the program's PTY takes typed keys, as the newest frame said.
    tty: Option<TtyModes>,
    /// Trust from the last connection to the same session, given once a frame shows known modes
    /// that are not a password prompt.
    carried: bool,
    line: Line,
}

/// The epoch a fresh predictor guesses in, one ahead of the confirmed one, so the first keystroke
/// stays hidden until the server proves it echoes: a password typed at a silent prompt never shows.
const FIRST_EPOCH: u64 = 1;

impl Default for PredictionEngine {
    fn default() -> Self {
        Self {
            cells: BTreeMap::new(),
            cursor: None,
            prediction_epoch: FIRST_EPOCH,
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
    fn context<'a>(&self, screen: &'a Screen) -> Option<Context<'a>> {
        let (rows, cols) = screen.size().into();
        let tty = self.tty.filter(|tty| !tty.password())?;
        (!screen.mode(Mode::AlternateScreen) && rows > 0 && cols > 0).then_some(Context {
            screen,
            tty,
            rows,
            cols,
        })
    }

    /// What a cell shows, predicted if there is a prediction; `None` if it is not known.
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

    /// Predict the typed glyph `cell` at `(row, col)`, and if it is wide, the cell it covers.
    fn place_glyph(&mut self, ctx: &Context<'_>, (row, col): (u16, u16), cell: Cell) {
        let covered = (cell.half == Half::Wide).then(|| Cell {
            text: String::new(),
            attributes: cell.attributes,
            half: Half::Covered,
        });
        self.place(ctx, (row, col), Some(cell), true);
        if let (Some(covered), Some(right)) = (covered, col.checked_add(1)) {
            self.place(ctx, (row, right), Some(covered), true);
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
    fn cursor_at(&self, screen: &Screen) -> (u16, u16) {
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
        let next = row.checked_add(1).filter(|&next| next < ctx.rows);
        self.move_cursor((next.unwrap_or(row), 0));
    }

    /// The first key of a line was typed: it began where the screen shows the cursor, unless the
    /// screen does not show the Enter yet, or a guess for the cursor is pending, when where is
    /// not known.
    fn begin_line(&mut self, screen: &Screen) {
        if let Line::Fresh(enter) = self.line {
            self.line = if self.cursor.is_none() && self.late_acked >= enter {
                let (row, col) = screen.cursor_position();
                Line::Started(row, col)
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

    /// The cell at `(row, col)`, predicted or not, if it is a narrow blank.
    fn blank(&self, ctx: &Context<'_>, row: u16, col: u16) -> Option<Cell> {
        self.guess_at(ctx, row, col).filter(Cell::blank)
    }

    /// Predict the grapheme `c` continues or begins, typed at the cursor onto blank cells: over
    /// text a line editor moves the rest of the row right, to where is not known.
    ///
    /// A character that continues the glyph before the cursor (an emoji's skin tone, a combining
    /// mark, the rest of an IME's cluster) joins it, as the terminal joins it when it is echoed:
    /// one glyph however many keys typed it, or nothing if joining would change its width. A
    /// glyph reaching the last column, where the terminal may wrap, opens a new epoch.
    fn predict_glyph(&mut self, ctx: &Context<'_>, c: char) {
        if ctx.tty.echo {
            // The kernel echoes it, so the program need not prove it does: the first epoch is
            // trusted. An epoch a later key opened still waits for its echo.
            self.confirmed_epoch = self.confirmed_epoch.max(FIRST_EPOCH);
        }
        let (row, col) = self.cursor_at(ctx.screen);
        if let Some((at, before)) = self.glyph_before(ctx, row, col) {
            if fux_vt::continues_cluster(&before.text, c) {
                let mut joined = before.clone();
                joined.text.push(c);
                if joined.text.width() != before.text.width() {
                    return self.unmodelled();
                }
                self.place_glyph(ctx, (row, at), joined);
                return self.move_cursor((row, col));
            }
        }
        let text = c.to_string();
        let width = u16::try_from(text.width()).unwrap_or(u16::MAX);
        let Some(end) = col
            .checked_add(width)
            .filter(|&end| width > 0 && end <= ctx.cols)
        else {
            return self.unmodelled();
        };
        if !(col..end).all(|at| self.blank(ctx, row, at).is_some()) {
            return self.unmodelled();
        }
        let attributes = col
            .checked_sub(1)
            .and_then(|left| self.guess_at(ctx, row, left))
            .filter(|left| !left.text.is_empty() || left.half == Half::Covered)
            .map_or_else(Attributes::default, |left| left.attributes);
        let half = if width == 2 { Half::Wide } else { Half::Narrow };
        let glyph = Cell {
            text,
            attributes,
            half,
        };
        self.place_glyph(ctx, (row, col), glyph);
        if end < ctx.cols {
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

    /// Whether Backspace or Left may step back from `(row, col)`: never past where the line began
    /// if that is known, else only over a glyph this line's own guesses typed, so the prompt
    /// before a line whose start is not known (just connected, or after Up or Tab) is never
    /// taken for it.
    fn may_step_back(&self, row: u16, col: u16) -> bool {
        match self.line {
            Line::Started(start_row, start) if start_row == row => col > start,
            Line::Started(..) | Line::Fresh(_) | Line::Unknown => col
                .checked_sub(1)
                .and_then(|left| self.cells.get(&(row, left)))
                .is_some_and(|cell| cell.typed),
        }
    }

    /// Backspace at a line's end (a blank at the cursor): the narrow glyph before it erased, as
    /// [`may_step_back`](Self::may_step_back) allows. Before text, a line editor moves the rest of
    /// the row left: not predicted.
    fn predict_backspace(&mut self, ctx: &Context<'_>) {
        let (row, col) = self.cursor_at(ctx.screen);
        let left = col.checked_sub(1).filter(|&left| {
            self.may_step_back(row, col)
                && self
                    .guess_at(ctx, row, left)
                    .is_some_and(|g| g.half == Half::Narrow)
        });
        match (left, self.blank(ctx, row, col)) {
            (Some(left), Some(blank)) => {
                self.place(ctx, (row, left), Some(blank), false);
                self.move_cursor((row, left));
            }
            _ => self.unmodelled(),
        }
    }

    /// Left or Right (`right`): the cursor one column over, within the row (Right stops before
    /// the last column), and Left as [`may_step_back`](Self::may_step_back) allows.
    fn predict_arrow(&mut self, ctx: &Context<'_>, right: bool) {
        let (row, col) = self.cursor_at(ctx.screen);
        let to = if right {
            col.checked_add(1).filter(|&next| next < ctx.cols)
        } else {
            col.checked_sub(1).filter(|_| self.may_step_back(row, col))
        };
        match to {
            Some(to) => self.move_cursor((row, to)),
            None => self.unmodelled(),
        }
    }

    /// Predict what the edit key `press` does to `screen`, after culling the existing predictions.
    /// The key is read as what it is, whatever the user's terminal sent for it: a control is its
    /// letter with Ctrl.
    ///
    /// Where the line begins is tracked whatever is predicted: Enter begins a line, whose first
    /// printable key says where.
    pub fn new_user_key(&mut self, press: KeyPress, screen: &Screen) {
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
                'h' => self.predict_backspace(&ctx),
                'j' | 'm' => self.predict_enter(&ctx),
                _ => self.unmodelled(),
            },
            (Key::Char(c), false, false) if !c.is_control() => self.predict_glyph(&ctx, c),
            (Key::Backspace, false, false) => self.predict_backspace(&ctx),
            (Key::Enter, false, false) => self.predict_enter(&ctx),
            // The kernel echoes an arrow as `^[[D`: only a line editor moves the cursor.
            (Key::Arrow(d @ (Direction::Right | Direction::Left)), false, false)
                if !ctx.tty.echo =>
            {
                self.predict_arrow(&ctx, d == Direction::Right);
            }
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
    pub fn new_user_other(&mut self, screen: &Screen) {
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
    pub fn cull(&mut self, screen: &Screen) {
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
        if matches!(self.line, Line::Started(..)) {
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
    screen: &Screen,
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

fn cursor_validity(cur: &Guessed, screen: &Screen, late_acked: u64) -> Validity {
    let (rows, cols) = screen.size().into();
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

    use fux_vt::Color;

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

    /// Type `bytes` as a legacy terminal sends them: each key decoded, then predicted.
    fn type_bytes(e: &mut PredictionEngine, bytes: &[u8], screen: &Screen) {
        let mut decoder = fux_vt::keys::decode::Decoder::default();
        let mut inputs = Vec::new();
        decoder.bytes(bytes, &mut inputs);
        decoder.timeout(&mut inputs);
        for input in inputs {
            if let fux_vt::keys::decode::Input::Key(key) = input {
                e.new_user_key(key.press, screen);
            }
        }
    }

    /// Type `keys` into `e` over `screen`, in an input frame the server has not reflected yet.
    fn type_keys(e: &mut PredictionEngine, screen: &Screen, keys: &[u8]) {
        e.set_local_frame_sent(e.late_acked);
        type_bytes(e, keys, screen);
    }

    fn cell_at(ov: &Overlay, row: u16, col: u16) -> Option<&Cell> {
        ov.cells.get(&(row, col))
    }

    /// The glyph predicted shown at `(row, col)`.
    fn shown_at(e: &PredictionEngine, row: u16, col: u16) -> Option<String> {
        cell_at(&e.overlay(), row, col).map(|c| c.text().to_owned())
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

        /// Whatever keys arbitrary bytes decode to, predicting them never panics.
        #[test]
        fn prop_predicting_any_keys_is_panic_free(
            bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..256),
        ) {
            let mut pe = engine();
            type_bytes(&mut pe, &bytes, &screen_of(b"ready prompt $ "));
            let _ = pe.overlay();
        }

        /// Whatever is typed over a screen of wide glyphs, a wide glyph the overlay shows has the
        /// next cell covered, and a covered cell follows one: the renderer draws them whole.
        #[test]
        fn predicted_wide_glyphs_are_shown_whole(
            bytes in proptest::collection::vec(
                proptest::sample::select(
                    [&b"a"[..], "日".as_bytes(), "\u{1f44d}".as_bytes(), "\u{1f3fd}".as_bytes(), b"\x7f", b"\x1b[D", b"\x1b[C", b"\r"]
                        .to_vec(),
                ),
                0..40,
            ),
            start in 0u16..12,
        ) {
            let screen = sized_screen_of(3, 12, format!("本x日 ab本\x1b[1;{}H", start.saturating_add(1)).as_bytes());
            let mut e = engine();
            for key in bytes {
                type_bytes(&mut e, key, &screen);
                // Everything shown: the check is on what the overlay holds, not on when it shows.
                e.confirm_for_tests();
                let ov = e.overlay();
                for ((row, col), cell) in ov.cells() {
                    let left = col.checked_sub(1).and_then(|left| cell_at(&ov, row, left));
                    let right = col.checked_add(1).and_then(|right| cell_at(&ov, row, right));
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

    /// Type `x` (hidden), have the server echo it and ack it, and grade it: later typing shows.
    fn confirm_first_keystroke() -> (PredictionEngine, Screen) {
        let mut e = engine();
        type_keys(&mut e, &screen_of(b""), b"x");
        assert!(
            e.overlay().is_empty(),
            "the very first keystroke must be hidden until the server confirms it echoes"
        );
        let echoed = screen_of(b"x");
        e.set_local_frame_late_acked(1);
        e.cull(&echoed);
        (e, echoed)
    }

    /// A predictor trusted at a line editor, on `bytes`' screen.
    fn editor_on(bytes: &[u8]) -> (PredictionEngine, Screen) {
        let mut e = engine();
        e.confirm_for_tests();
        let screen = screen_of(bytes);
        e.cull(&screen);
        (e, screen)
    }

    /// A trusted predictor at a `$ ` prompt drawn after Enter: where the line begins is known.
    fn fresh_line() -> (PredictionEngine, Screen) {
        let (mut e, screen) = editor_on(b"$ ");
        type_keys(&mut e, &screen, b"\r");
        e.set_local_frame_late_acked(1);
        e.cull(&screen);
        e.confirm_for_tests();
        (e, screen)
    }

    /// Row 0 as shown: the overlay over the screen, trailing blanks trimmed; and the cursor's
    /// column as predicted.
    fn shown_row(e: &PredictionEngine, screen: &Screen) -> (String, Option<u16>) {
        let ov = e.overlay();
        let text: String = (0..80)
            .map(|col| match cell_at(&ov, 0, col) {
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

    #[test]
    fn no_echo_keeps_secret_hidden_and_cleans_up() {
        // A secret typed before any server confirmation is never drawn, and one the server never
        // echoes (a password prompt) is culled away.
        let mut e = engine();
        type_keys(&mut e, &screen_of(b""), b"hunter2");
        assert!(e.overlay().is_empty(), "non-echoed input is never shown");
        e.set_local_frame_late_acked(1);
        e.cull(&screen_of(b""));
        assert!(e.overlay().is_empty() && e.cells.is_empty());
    }

    /// A right-side prompt stays where it is as the line is typed and erased, so it never
    /// contradicts a guess; a key typed over text, which a line editor moves, is not guessed.
    #[test]
    fn a_right_side_prompt_does_not_stop_prediction() {
        let rprompt = |line: &str, col: u16| {
            screen_of(format!("$ {line}\x1b[1;76H~/src\x1b[1;{col}H").as_bytes())
        };
        let (mut e, screen) = editor_on(b"$ \x1b[1;76H~/src\x1b[1;3H");
        type_keys(&mut e, &screen, b"lss\x7f");
        let typed = format!("$ ls{}~/src", " ".repeat(71));
        assert_eq!(shown_row(&e, &screen), (typed, Some(4)));
        // The echo confirms every guess and kills none: the next key shows at once.
        e.set_local_frame_late_acked(1);
        let echoed = rprompt("ls", 5);
        e.cull(&echoed);
        type_keys(&mut e, &echoed, b" ");
        assert_eq!(shown_row(&e, &echoed).1, Some(5));
        let (mut e, screen) = editor_on(b"$ ab\x1b[1;4H");
        type_keys(&mut e, &screen, b"x");
        assert!(e.overlay().is_empty(), "typed over the b");
    }

    #[test]
    fn correct_grade_restyles_the_pending_typed_glyphs_right_of_it() {
        // mosh "match rest of row to the actual renditions": when a typed glyph confirms in a
        // style, the still-pending typed glyphs to its right take that whole style (so they don't
        // flash a guessed one before their own frame confirms).
        let (mut e, echoed) = confirm_first_keystroke();
        // 'b' on frame 2 (will be confirmed), 'c' on frame 3 (stays pending).
        e.set_local_frame_sent(1);
        type_bytes(&mut e, b"b", &echoed);
        e.set_local_frame_sent(2);
        type_bytes(&mut e, b"c", &echoed);
        let style = |e: &PredictionEngine| cell_at(&e.overlay(), 0, 2).map(Cell::attributes);
        assert_eq!(style(&e), Some(Attributes::default()), "guessed");
        // The server echoes 'b' bold red and acks frame 2.
        let colored = screen_of(b"x\x1b[1;31mb");
        e.set_local_frame_late_acked(2);
        e.cull(&colored);
        let confirmed = colored.cell(0, 1).map(|c| c.attributes());
        assert!(confirmed.is_some_and(|a| a.bold() && a.foreground() == Color::Idx(1)));
        assert_eq!(style(&e), confirmed, "'c' takes 'b''s whole style");
    }

    /// A typed glyph borrows its left neighbour's whole style, hidden included, as the echo will
    /// show it.
    #[test]
    fn a_typed_glyph_takes_its_neighbours_style() {
        let (mut e, screen) = editor_on(b"\x1b[8;1;31ma\x1b[m");
        type_keys(&mut e, &screen, b"X");
        let style = cell_at(&e.overlay(), 0, 1).map(Cell::attributes);
        assert_eq!(style, screen.cell(0, 0).map(|c| c.attributes()));
        assert!(style.is_some_and(|a| a.hidden() && a.bold()));
    }

    /// An emoji with a skin tone, typed in one keystroke or two (an IME commits it as two
    /// characters), or after the screen shows the emoji, is one glyph, as the terminal joins it.
    #[test]
    fn a_grapheme_typed_in_pieces_is_one_glyph() {
        let (mut e, echoed) = confirm_first_keystroke();
        type_keys(&mut e, &echoed, "\u{1f44d}\u{1f3fd}a".as_bytes());
        let ov = e.overlay();
        assert_eq!(
            cell_at(&ov, 0, 1).map(Cell::text),
            Some("\u{1f44d}\u{1f3fd}")
        );
        assert!(cell_at(&ov, 0, 2).is_some_and(Cell::covered));
        assert_eq!(cell_at(&ov, 0, 3).map(Cell::text), Some("a"));
        assert_eq!(ov.cursor(), Some((0, 4)));
        let (mut e, screen) = editor_on("\u{1f44d}".as_bytes());
        type_keys(&mut e, &screen, "\u{1f3fd}".as_bytes());
        assert_eq!(shown_at(&e, 0, 0).as_deref(), Some("\u{1f44d}\u{1f3fd}"));
        assert!(cell_at(&e.overlay(), 0, 1).is_some_and(Cell::covered));
        // A joiner that would make the glyph wider is not guessed at all.
        let (mut e, echoed) = confirm_first_keystroke();
        let epoch = e.prediction_epoch;
        type_keys(&mut e, &echoed, "\u{2764}\u{fe0f}".as_bytes());
        assert!(
            e.prediction_epoch > epoch,
            "the heart's widening opened a new epoch"
        );
        assert!(shown_at(&e, 0, 1).is_none_or(|g| g == "\u{2764}"));
    }

    #[test]
    fn prediction_reassembles_multibyte_utf8_no_stray_byte() {
        // mosh prediction-unicode regression: typing "glück" must predict 'ü', and "faĩl" 'ĩ',
        // not the low byte of the code point.
        for (word, accent) in [("glück", "ü"), ("faĩl", "ĩ")] {
            let (mut e, echoed) = confirm_first_keystroke();
            type_keys(&mut e, &echoed, word.as_bytes());
            assert_eq!(shown_at(&e, 0, 3).as_deref(), Some(accent), "{word}");
            assert!(
                e.overlay().cells().all(|(_, c)| c.text() != ")"),
                "{word}: ĩ must not collapse to its low byte ')'"
            );
        }
    }

    /// The line begins where a frame shows the cursor, never where a guess put it: after Enter
    /// the prompt is drawn where the guess put the cursor, so a key typed before the frame that
    /// shows it leaves the line's start unknown.
    #[test]
    fn the_line_begins_at_a_confirmed_cursor_not_a_guessed_one() {
        let (mut e, screen) = editor_on(b"$ ls");
        type_keys(&mut e, &screen, b"\rx");
        assert_eq!(
            e.line,
            Line::Unknown,
            "a guess was pending at the first key"
        );
        let (mut e, screen) = editor_on(b"$ ls");
        type_keys(&mut e, &screen, b"\r");
        let prompt = screen_of(b"$ ls\r\nfile\r\n$ ");
        e.set_local_frame_late_acked(1);
        e.cull(&prompt);
        type_keys(&mut e, &prompt, b"ab");
        assert_eq!(e.line, Line::Started(2, 2));
        // A discarded guess takes the line's start with it.
        e.reset();
        assert_eq!(e.line, Line::Unknown);
    }

    #[test]
    fn backspace_and_left_never_go_past_where_the_line_began() {
        for key in [&b"\x7f"[..], b"\x1b[D", b"\x08"] {
            // Where the line began is known: back over what was typed, echoed or not.
            let (mut e, screen) = fresh_line();
            type_keys(&mut e, &screen, b"ab");
            let echoed = screen_of(b"$ ab");
            e.set_local_frame_late_acked(2);
            e.cull(&echoed);
            assert!(e.cells.is_empty(), "the echo confirmed what was typed");
            for col in [3, 2, 2] {
                type_keys(&mut e, &echoed, key);
                assert_eq!(shown_row(&e, &echoed).1, Some(col), "{key:?}");
            }
            // Not known: only over what this line's own guesses typed.
            let (mut e, screen) = editor_on(b"$ ");
            type_keys(&mut e, &screen, b"ab");
            for col in [3, 2, 2] {
                type_keys(&mut e, &screen, key);
                assert_eq!(shown_row(&e, &screen).1, Some(col), "{key:?}");
            }
        }
        // A line editor deletes both halves of a wide glyph: not guessed.
        let (mut e, screen) = fresh_line();
        type_keys(&mut e, &screen, "本".as_bytes());
        let epoch = e.prediction_epoch;
        type_keys(&mut e, &screen, b"\x7f");
        assert!(e.prediction_epoch > epoch);
        assert_eq!(shown_row(&e, &screen), ("$ 本".to_owned(), Some(4)));
    }

    /// Line-editing keys move the cursor or the text by rules a guess cannot be sure of (where
    /// the line began, where it ends before a right-side prompt): never guessed. An escape
    /// sequence is read whole, so none draws a stray `~` or `C`.
    #[test]
    fn line_editing_keys_are_not_predicted() {
        for keys in [
            &b"\x17"[..],
            b"\x15",
            b"\x01",
            b"\x05",
            b"\x1b[H",
            b"\x1b[F",
            b"\x1bb",
            b"\x1bf",
            b"\x1b\x7f",
            b"\x1b[3~",
            b"\x1b[1;5C",
        ] {
            let (mut e, screen) = fresh_line();
            type_keys(&mut e, &screen, b"ab");
            let epoch = e.prediction_epoch;
            type_keys(&mut e, &screen, keys);
            assert_eq!(
                shown_row(&e, &screen),
                ("$ ab".to_owned(), Some(4)),
                "{keys:?}"
            );
            assert!(e.prediction_epoch > epoch, "{keys:?} opened a new epoch");
        }
    }

    #[test]
    fn a_password_prompt_shows_nothing_typed_even_after_trust() {
        let (mut e, screen) = editor_on(b"$ ");
        type_keys(&mut e, &screen, b"sudo");
        assert!(!e.overlay().is_empty(), "trusted at the shell");
        let mut carried = e.reattached();
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
        carried.set_tty(Some(password));
        type_keys(&mut carried, &prompt, b"hunter2");
        assert!(carried.overlay().is_empty());
    }

    /// Modes not known are not a password prompt's, nor anything else's: carried trust waits
    /// for known ones.
    #[test]
    fn carried_trust_waits_for_known_modes() {
        let (e, screen) = editor_on(b"$ ");
        let mut e = e.reattached();
        e.set_tty(None);
        type_keys(&mut e, &screen, b"a");
        assert!(e.overlay().is_empty() && e.cells.is_empty());
        e.set_tty(Some(EDITOR));
        type_keys(&mut e, &screen, b"b");
        assert_eq!(shown_at(&e, 0, 2).as_deref(), Some("b"));
    }

    /// The kernel's echo needs no proof from the program, but a key not modelled (Tab here) still
    /// hides what follows until its echo.
    #[test]
    fn kernel_echo_is_trusted_from_the_first_key_until_an_unmodelled_one() {
        let mut e = PredictionEngine::default();
        let screen = screen_of(b"");
        e.set_tty(Some(TtyModes {
            echo: true,
            line: true,
        }));
        type_keys(&mut e, &screen, b"hi");
        assert_eq!(shown_row(&e, &screen), ("hi".to_owned(), Some(2)));
        type_keys(&mut e, &screen, b"\tx");
        assert_eq!(shown_row(&e, &screen), ("hi".to_owned(), None));
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
