//! # koh-predict — the local-echo prediction engine
//!
//! What makes typing feel instant on a laggy link. When the user types, the client *guesses*
//! what each keystroke does to the screen and displays it immediately, then confirms or corrects
//! when the authoritative server frame arrives.
//!
//! ## What it does
//!
//! Instant echo of ordinary typing, with epoch-gated confirmation driven by the server's debounced
//! **echo-ack** (not the raw network ack), engagement by round-trip time, and emergent
//! password/no-echo suppression. It predicts ASCII printables, backspace, CR/LF, the left/right
//! arrow keys, and
//! whole UTF-8 graphemes (including double-width CJK/emoji, whose cursor advances by two
//! cells). Control/escape/CSI bytes it doesn't model (and ambiguous edge-of-row cases) open a
//! fresh epoch but make no concrete prediction — they fall back to the server's real echo.
//! This never corrupts the display — a wrong or unconfirmed guess is reconciled away — it just
//! doesn't *speed up* those rarer cases.
//!
//! The render-facing output is an [`Overlay`]: the cells to draw speculatively and the
//! predicted cursor position. It is empty whenever the display policy says "don't show."

use std::collections::{BTreeMap, BTreeSet};

use unicode_width::UnicodeWidthStr;
use fux_vt::Color;

/// One cell as the predictor sees it: the glyph (empty for a blank or a wide-glyph continuation)
/// and its colours.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CellView<'a> {
    pub contents: &'a str,
    pub fg: Color,
    pub bg: Color,
}

/// The read-only view of an authoritative screen the predictor reconciles against (KC-01).
///
/// koh's client grid (`terminal::Grid`) and `fux_vt::Screen` implement it, and the tests implement
/// it for a plain char grid. It keeps `predict` free of any `crate::` import (the CI layering guard
/// enforces that).
pub trait ScreenView {
    /// `(rows, cols)`.
    fn size(&self) -> (u16, u16);
    /// The cursor as `(row, col)`, 0-indexed.
    fn cursor_position(&self) -> (u16, u16);
    /// The cell at `(row, col)`, or `None` when out of bounds.
    fn cell(&self, row: u16, col: u16) -> Option<CellView<'_>>;
}

impl ScreenView for fux_vt::Screen {
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

/// When predictions are drawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayPreference {
    /// Always render predictions.
    Always,
    /// Never predict (the plain, non-speculative path).
    Never,
    /// Render only while the link is slow enough to benefit.
    Adaptive,
}

/// [`Adaptive`](DisplayPreference::Adaptive) starts showing predictions once the round-trip time
/// rises above this, and stops once it falls below [`DISENGAGE_BELOW_MS`]. The gap is hysteresis,
/// so a link hovering near the threshold does not flicker predictions on and off.
const ENGAGE_ABOVE_MS: f64 = 60.0;
const DISENGAGE_BELOW_MS: f64 = 40.0;

/// A speculative cell for the renderer to draw on top of the authoritative grid.
#[derive(Clone, Debug)]
pub struct PredictedCell {
    /// The predicted glyph. **Empty when [`unknown`](PredictedCell::unknown)** — the renderer
    /// must then only hint (underline the existing real cell), never overwrite its content.
    pub glyph: String,
    pub fg: Color,
    pub bg: Color,
    /// Whether to underline it. Always false now; kept because the renderer reads it.
    pub underline: bool,
    /// "Something changed here but we don't know what" (e.g. content shifted in from off-screen
    /// by an insert/backspace). Rendered as an underline-only hint, never a guessed glyph.
    pub unknown: bool,
}

/// The render-facing snapshot of current predictions.
#[derive(Default, Debug)]
pub struct Overlay {
    cells: BTreeMap<(u16, u16), PredictedCell>,
    cursor: Option<(u16, u16)>,
}

impl Overlay {
    pub fn empty() -> Self {
        Self::default()
    }
    /// The predicted cell at `(row, col)`, if any.
    pub fn cell(&self, row: u16, col: u16) -> Option<&PredictedCell> {
        self.cells.get(&(row, col))
    }
    /// The predicted cursor position `(row, col)`, if any.
    pub fn cursor(&self) -> Option<(u16, u16)> {
        self.cursor
    }
    pub fn is_empty(&self) -> bool {
        self.cells.is_empty() && self.cursor.is_none()
    }
}

#[derive(Clone)]
struct PredCell {
    expiration_frame: u64,
    tentative_epoch: u64,
    glyph: String,
    fg: Color,
    bg: Color,
    /// The prior content at this cell (the glyph being overwritten) so a rewrite that lands back on
    /// that earlier value grades "no credit" (can't falsely confirm an epoch). `None` for an
    /// `unknown` cell, which never grades against it. Was a `Vec` (only ever 0/1 elements); an
    /// `Option` drops the per-cell heap-vec on the O(cols)/keystroke row-shift path.
    original_contents: Option<String>,
    /// "Changed here, not sure what" — never drawn as a glyph; underline-only hint.
    unknown: bool,
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

/// Tracks a multi-byte escape sequence across `new_user_byte` calls (input arrives one byte at
/// a time), so escape bytes are consumed rather than mis-drawn as literal glyphs.
#[derive(PartialEq, Eq, Clone, Copy)]
enum EscState {
    /// Not mid-escape.
    Ground,
    /// Saw `ESC`.
    Esc,
    /// Saw `ESC [` (also covers `ESC O` after normalization) — awaiting the final byte.
    Csi,
}

/// The prediction engine.
///
/// Drive it: [`set_local_frame_sent`](Self::set_local_frame_sent)
/// before feeding typed bytes; [`new_user_byte`](Self::new_user_byte) per typed byte;
/// [`set_local_frame_late_acked`](Self::set_local_frame_late_acked) + [`set_rtt_ms`](Self::set_rtt_ms)
/// + [`cull`](Self::cull) when a server frame arrives; [`overlay`](Self::overlay) to render.
pub struct PredictionEngine {
    pref: DisplayPreference,
    cells: BTreeMap<(u16, u16), PredCell>,
    cursor: Option<PredCursor>,
    prediction_epoch: u64,
    confirmed_epoch: u64,
    local_frame_sent: u64,
    late_acked: u64,
    /// The link round-trip time (ms) the client last reported, for adaptive engagement.
    rtt_ms: f64,
    /// Whether adaptive engagement is currently showing predictions (latched, with hysteresis).
    engaged: bool,
    last_size: Option<(u16, u16)>,
    last_byte: u8,
    /// Escape-sequence parser state across raw input bytes (for arrow-key prediction).
    esc: EscState,
    /// Partial UTF-8 sequence accumulated across calls (input arrives one byte at a time), and
    /// the total byte length its leading byte announced. Empty/0 when not mid-grapheme.
    utf8_buf: Vec<u8>,
    utf8_need: usize,
}

impl PredictionEngine {
    /// A predictor displaying per `pref`.
    pub fn new(pref: DisplayPreference) -> Self {
        Self {
            pref,
            cells: BTreeMap::new(),
            cursor: None,
            // SECURITY: predictions start one epoch *ahead* of what's confirmed, so a freshly
            // typed character (stamped `prediction_epoch = 1`) is tentative — `tentative(0)` is
            // `1 > 0` = true — and therefore hidden until the server proves it echoes by
            // advancing `confirmed_epoch` to 1 (a `Correct` validation in `cull`). This is what
            // keeps a password typed into a non-echoing prompt from flashing on screen. Starting
            // both at 0 would draw the first keystroke before any server confirmation.
            prediction_epoch: 1,
            confirmed_epoch: 0,
            local_frame_sent: 0,
            late_acked: 0,
            rtt_ms: 0.0,
            engaged: false,
            last_size: None,
            last_byte: 0,
            esc: EscState::Ground,
            utf8_buf: Vec::new(),
            utf8_need: 0,
        }
    }

    /// Read the predicted-or-real glyph + style + unknown-ness at a cell — the source content a
    /// row-shift copies from. Prefers an active prediction over the authoritative screen.
    fn pred_or_real_glyph(
        &self,
        screen: &dyn ScreenView,
        row: u16,
        col: u16,
    ) -> (String, Color, Color, bool) {
        if let Some(p) = self.cells.get(&(row, col)) {
            (p.glyph.clone(), p.fg, p.bg, p.unknown)
        } else {
            let (fg, bg) = glyph_style(screen, row, col);
            (cell_glyph(screen, row, col), fg, bg, false)
        }
    }

    /// Insert a prediction cell at `(row, col)`, stamping the shared, load-bearing invariant: the
    /// expiration frame (`local_frame_sent + 1`), the current `prediction_epoch` (the security gate
    /// that hides input until the server confirms it echoes), and a one-element
    /// `original_contents` snapshot of the cell being overwritten (so a rewrite back to an earlier
    /// value grades "no credit"). Centralizes the identical invariant literals so a future edit can't
    /// drift one site's invariant on this security-sensitive path (S-07). The per-cell fields
    /// (`glyph`/`fg`/`bg`/`unknown`) vary and are passed in.
    ///
    /// `unknown` cells never grade against `original_contents` — [`cell_validity`] short-circuits them
    /// to `CorrectNoCredit` before reading it — so for them we skip the snapshot entirely (it would be
    /// a wasted heap `Vec` + glyph clone on the O(cols)-per-keystroke row-shift path).
    #[expect(
        clippy::too_many_arguments,
        reason = "the per-cell fields differ across the call sites; the invariant fields are stamped here"
    )]
    fn place_cell(
        &mut self,
        screen: &dyn ScreenView,
        row: u16,
        col: u16,
        glyph: String,
        fg: Color,
        bg: Color,
        unknown: bool,
    ) {
        self.cells.insert(
            (row, col),
            PredCell {
                expiration_frame: self.next_frame(),
                tentative_epoch: self.prediction_epoch,
                glyph,
                fg,
                bg,
                original_contents: if unknown {
                    None
                } else {
                    Some(cell_glyph(screen, row, col))
                },
                unknown,
            },
        );
    }

    /// The newest epoch the server has confirmed echoes (predictions at or below it may show) —
    /// bumped by [`cull`](Self::cull) when a prediction is confirmed. Test-only.
    #[cfg(test)]
    pub fn confirmed_epoch(&self) -> u64 {
        self.confirmed_epoch
    }
    /// The newest local input frame number sent so far (predictions expire at this + 1).
    pub fn set_local_frame_sent(&mut self, n: u64) {
        self.local_frame_sent = n;
    }
    /// The server's echo-ack: the newest input frame reflected on screen.
    pub fn set_local_frame_late_acked(&mut self, n: u64) {
        self.late_acked = n;
    }
    /// The link round-trip time (ms), for adaptive engagement (with hysteresis).
    pub fn set_rtt_ms(&mut self, ms: f64) {
        self.rtt_ms = ms;
        if ms > ENGAGE_ABOVE_MS {
            self.engaged = true;
        } else if ms < DISENGAGE_BELOW_MS {
            self.engaged = false;
        }
    }

    /// The frame a prediction made now expires at: the next input frame after the newest sent.
    /// Frame numbers count sent states and cannot reach `u64::MAX` in practice. Were one to, the
    /// expiry saturates there, the last frame there is, instead of wrapping to an expired 0.
    fn next_frame(&self) -> u64 {
        self.local_frame_sent.saturating_add(1)
    }

    fn become_tentative(&mut self) {
        // One epoch per tentative event, so `u64::MAX` is out of reach. Saturating keeps the epoch
        // from wrapping below `confirmed_epoch`, which would show unconfirmed predictions.
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
        let (rows, _) = screen.size();
        self.init_cursor(screen);
        if let Some(c) = self.cursor.as_mut() {
            c.col = 0;
            if let Some(next) = c.row.checked_add(1).filter(|&next| next < rows) {
                c.row = next;
            }
            // On the last row we do NOT predict a scroll (mosh deliberately avoids it).
        }
    }

    /// Predict a horizontal cursor move (`dir > 0` = right, `dir < 0` = left), clamped to the
    /// row. Cursor-only prediction in the current epoch, confirmed via `cursor_validity`; like
    /// a typed char it does not open a new epoch. Vertical arrows are not predicted (the caller
    /// `become_tentative`s them).
    fn predict_arrow(&mut self, screen: &dyn ScreenView, dir: i32) {
        self.init_cursor(screen);
        let exp = self.next_frame();
        let (_, cols) = screen.size();
        if let Some(c) = self.cursor.as_mut() {
            // Right stops before the last column, left at column 0. The width is peer-controlled,
            // so the step is checked: at `u16::MAX` or with `cols == 0` the cursor just stays.
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

    /// Predict a full UTF-8 grapheme `g` (already decoded from accumulated bytes). Places the
    /// glyph at the cursor and advances by its display width — two cells for CJK/emoji, whose
    /// continuation cell the emulator leaves empty (so we predict nothing there). Zero-width
    /// (combining) graphemes and ones that would land on the wrap-ambiguous right edge fall back
    /// to a tentative epoch. Overwrite-only (no insert-mode tail shift for wide chars — that
    /// rarer case is left to the server's real echo).
    fn predict_wide(&mut self, g: &str, screen: &dyn ScreenView) {
        // `g` is one decoded char, so its width is at most 2. Clamping keeps a wider one on the
        // "does not fit" path below instead of truncating it into a small width.
        let w = u16::try_from(g.width()).unwrap_or(u16::MAX);
        if w == 0 {
            self.become_tentative(); // combining / zero-width: can't place safely
            return;
        }
        let (_, cols) = screen.size();
        let (row, col) = {
            let c = self.init_cursor(screen);
            (c.row, c.col)
        };
        // Need the whole glyph to fit strictly before the last column (the edge is wrap-ambiguous).
        // `col + w` is checked: the width is peer-controlled, and an overflow cannot fit either.
        let Some(next_col) = col.checked_add(w).filter(|&next| next < cols) else {
            self.become_tentative();
            self.init_cursor(screen);
            return;
        };
        let exp = self.next_frame();
        let (fg, bg) = glyph_style(screen, row, col);
        self.place_cell(screen, row, col, g.to_string(), fg, bg, false);
        if let Some(c) = self.cursor.as_mut() {
            c.expiration_frame = exp;
            c.col = next_col;
        }
    }

    /// Record a typed byte and speculate its on-screen effect against `screen` (the latest
    /// authoritative frame). Validates existing predictions first (`cull`).
    pub fn new_user_byte(&mut self, byte: u8, screen: &dyn ScreenView) {
        if self.pref == DisplayPreference::Never {
            return;
        }
        self.cull(screen);

        let mut byte = byte;
        if self.last_byte == 0x1b && byte == b'O' {
            byte = b'['; // application-cursor-mode arrow normalization
        }
        self.last_byte = byte;

        let (rows, cols) = screen.size();
        if rows == 0 || cols == 0 {
            return;
        }

        // Continue accumulating an in-progress UTF-8 grapheme; predict it once complete. Done
        // before the escape handling because continuation bytes (0x80..=0xbf) must never be
        // interpreted as escape finals.
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
            // Malformed (continuation expected, got something else): abandon the partial grapheme
            // and reprocess this byte from scratch below.
            self.utf8_buf.clear();
            self.utf8_need = 0;
            self.become_tentative();
        }

        // Consume bytes that belong to a multi-byte escape sequence (so they're never mis-drawn
        // as literal glyphs) and predict the common, safe left/right arrows. `ESC O x` was
        // normalized to `ESC [ x` above, so both cursor-key and application-cursor arrows land
        // in the `Csi` arm.
        match self.esc {
            EscState::Esc => {
                self.esc = if byte == b'[' {
                    EscState::Csi
                } else {
                    self.become_tentative(); // an escape we don't model -> wait for the server
                    EscState::Ground
                };
                return;
            }
            EscState::Csi => {
                self.esc = EscState::Ground;
                match byte {
                    b'C' => self.predict_arrow(screen, 1),  // right
                    b'D' => self.predict_arrow(screen, -1), // left
                    // up/down/home/end/parameterized (digits, ';'): can't predict safely, bail.
                    _ => self.become_tentative(),
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
                // Ordinary printable ASCII.
                let col = self.init_cursor(screen).col;
                // `col >= cols - 1`, saturating so a peer-controlled `cols == 0` can't overflow `+ 1`.
                if col >= cols.saturating_sub(1) {
                    // Last column is ambiguous (wrap vs. overwrite); hide until confirmed.
                    self.become_tentative();
                }
                let (row, col) = {
                    let c = self.init_cursor(screen);
                    (c.row, c.col)
                };
                // Insert mode (the only mode koh predicts): shift the row right (cols-1 down to
                // col+1) so the tail moves over to make room — matching what a readline-style line
                // editor renders. Iterate right-to-left so each cell reads its left neighbor's
                // pre-shift content.
                // Each `(left, i)` is a column and its left neighbor, from `(col, col + 1)` up.
                for (left, i) in (col..cols).zip((col..cols).skip(1)).rev() {
                    let (g, fg, bg, src_unknown) = self.pred_or_real_glyph(screen, row, left);
                    // The rightmost cell takes content pushed off-screen -> unknown.
                    let unknown = i.checked_add(1) == Some(cols) || src_unknown;
                    let glyph = if unknown { String::new() } else { g };
                    self.place_cell(screen, row, i, glyph, fg, bg, unknown);
                }
                let (fg, bg) = glyph_style(screen, row, col);
                self.place_cell(
                    screen,
                    row,
                    col,
                    (byte as char).to_string(),
                    fg,
                    bg,
                    false,
                );
                let exp = self.next_frame();
                if let Some(c) = self.cursor.as_mut() {
                    c.expiration_frame = exp;
                    // Advance unless on the last column (checked: `cols` is peer-controlled).
                    if let Some(next) = c.col.checked_add(1).filter(|&next| next < cols) {
                        c.col = next;
                    } else {
                        self.become_tentative();
                        self.newline_cr(screen);
                    }
                }
            }
            0x7f | 0x08 => {
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
                    // Insert mode (the only mode): shift the row left from col to the right edge;
                    // the last TWO columns gain whatever was off-screen -> unknown (underline hint,
                    // never a guessed glyph). mosh marks the cell unknown when `i + 2 >= width`
                    // (terminaloverlay.cc), one column wider than the naive "only the last column" —
                    // the right-edge cell a wide grapheme could straddle is ambiguous too.
                    // Left-to-right so each cell reads its unshifted right neighbor.
                    for i in col..cols {
                        // `i < cols - 2` is mosh's `i + 2 < width`, written to never overflow u16
                        // (the screen width is peer-controlled; `i + 2` would wrap/panic at
                        // cols == u16::MAX). It implies `i + 1 < cols`, so the right neighbor
                        // exists and the checked `i + 1` succeeds.
                        let right = i.checked_add(1).filter(|_| i < cols.saturating_sub(2));
                        let (g, fg, bg, unknown) = match right {
                            Some(right) => self.pred_or_real_glyph(screen, row, right),
                            None => (String::new(), Color::Default, Color::Default, true),
                        };
                        let glyph = if unknown { String::new() } else { g };
                        self.place_cell(screen, row, i, glyph, fg, bg, unknown);
                    }
                }
            }
            0x0d | 0x0a => {
                // CR/LF: can't predict scroll cleanly — open a new epoch and move the cursor.
                self.become_tentative();
                self.newline_cr(screen);
            }
            _ => {
                // Other C0 control bytes we don't model: open a new epoch, predict nothing.
                self.become_tentative();
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
        let (rows, cols) = size;

        let late = self.late_acked;
        let confirmed = self.confirmed_epoch;

        let mut to_remove: Vec<(u16, u16)> = Vec::new();
        let mut kill_epochs: BTreeSet<u64> = BTreeSet::new();
        let mut kill_all = false;
        let mut max_confirm = confirmed;
        // mosh's "match rest of row to the actual renditions": each `(row, from_col, fg, bg)` run
        // recolors the still-pending predicted cells from `from_col` to the row's end with a freshly
        // confirmed cell's *actual* colors, so they don't flash a guessed rendition before their own
        // frame lands. Applied after the validity pass (can't mutate `cells` while iterating it).
        let mut rendition_runs: Vec<(u16, u16, Color, Color)> = Vec::new();

        for (&(row, col), cell) in &self.cells {
            let v = cell_validity(cell, screen, row, col, rows, cols, late);
            match v {
                Validity::Pending => {}
                Validity::Correct => {
                    if cell.tentative_epoch > max_confirm {
                        max_confirm = cell.tentative_epoch;
                    }
                    // Re-color the rest of this row's pending predictions to the actual confirmed
                    // renditions (mosh terminaloverlay.cc): koh's `PredCell` carries only fg/bg, so
                    // this ports the color/attr-flicker fix to the extent the cell model allows.
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
        // Apply the deferred rest-of-row rendition copies to the cells that survived the validity
        // pass. Runs are in row-major / ascending-column order, so a later (further-right) confirmed
        // cell's colors win for the overlap — matching mosh's sequential per-cell application.
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
            // mosh's kill_epoch re-seeds a fresh cursor at the *real* screen position in the new
            // epoch, so a stale predicted cursor left over from the killed epoch can't keep being
            // drawn. It is tentative (epoch > confirmed) and therefore hidden until confirmed, so
            // the authoritative cursor shows through in the meantime.
            let (crow, ccol) = screen.cursor_position();
            self.cursor = Some(PredCursor {
                expiration_frame: self.next_frame(),
                tentative_epoch: self.prediction_epoch,
                row: crow,
                col: ccol,
            });
        }

        // Cursor validation.
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

    /// Build the render overlay for the current frame, honoring the display policy and epoch
    /// gating. Empty when nothing should be shown.
    pub fn overlay(&self) -> Overlay {
        let show = match self.pref {
            DisplayPreference::Never => false,
            DisplayPreference::Always => true,
            DisplayPreference::Adaptive => self.engaged,
        };
        if !show {
            return Overlay::empty();
        }
        let mut ov = Overlay::empty();
        for (&(row, col), cell) in &self.cells {
            if self.tentative(cell.tentative_epoch) {
                continue; // hidden until its epoch is confirmed
            }
            if cell.unknown {
                // "Something changed here, not sure what": show nothing, so the real cell beneath
                // stays visible rather than a guessed glyph.
                continue;
            }
            ov.cells.insert(
                (row, col),
                PredictedCell {
                    glyph: cell.glyph.clone(),
                    fg: cell.fg,
                    bg: cell.bg,
                    underline: false,
                    unknown: false,
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

    /// Reset the incremental byte decoder (the escape-sequence state machine + the partial-UTF-8
    /// buffer). [`reset`](Self::reset) runs on a resize; if that resize lands mid-escape or
    /// mid-grapheme, the leftover bytes would otherwise survive and mis-decode the next typed byte.
    fn reset_decoder(&mut self) {
        self.esc = EscState::Ground;
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
    // Copy the style of the neighbor to the left if it has content; else terminal default.
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
    let (rows, cols) = screen.size();
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

    use fux_vt::Screen;

    fn screen_of(bytes: &[u8]) -> Screen {
        let mut p = fux_vt::Parser::new(24, 80, 0).expect("24x80 parser");
        p.process(bytes).expect("process");
        p.screen().clone()
    }

    /// A screen that is NOT an emulator: a plain char grid with a cursor (KC-01).
    struct FakeView {
        rows: Vec<Vec<char>>,
        cursor: (u16, u16),
    }

    impl ScreenView for FakeView {
        fn size(&self) -> (u16, u16) {
            (self.rows.len() as u16, self.rows[0].len() as u16)
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
            })
        }
    }

    #[test]
    fn predictor_runs_over_a_plain_screen_view() {
        // KC-01: the exact flow of `confirm_first_keystroke`, but over a 5×10 fake grid that is
        // not an emulator: the first keystroke is hidden, the server's echo confirms the epoch, and the
        // next keystroke is visible at the right column. Proves the engine needs no emulator.
        let blank = FakeView {
            rows: vec![vec![' '; 10]; 5],
            cursor: (0, 0),
        };
        let mut e = PredictionEngine::new(DisplayPreference::Always);
        e.set_rtt_ms(250.0);
        e.set_local_frame_sent(0);
        e.new_user_byte(b'x', &blank);
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
        e.new_user_byte(b'y', &echoed);
        let ov = e.overlay();
        assert_eq!(
            ov.cell(0, 1).map(|c| c.glyph.as_str()),
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
        // byte. Regression: reset() used to clear the prediction cells/cursor but leave the decoder
        // (esc / utf8_buf / utf8_need / last_byte) stale.
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
    }

    /// Drive a confirmation round: type `first` (hidden), have the server echo it on `echoed`
    /// and ack frame 1, cull (advancing `confirmed_epoch`). Returns the engine ready for
    /// subsequent typing to be *visible*.
    fn confirm_first_keystroke(pref: DisplayPreference, srtt: f64) -> (PredictionEngine, Screen) {
        let mut e = PredictionEngine::new(pref);
        e.set_rtt_ms(srtt);
        e.set_local_frame_sent(0);
        let blank = screen_of(b"");
        e.new_user_byte(b'x', &blank);
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
        // even with Display::Always (proving the *epoch* gate, not the SRTT gate, suppresses it).
        let mut e = PredictionEngine::new(DisplayPreference::Always);
        e.set_local_frame_sent(0);
        let blank = screen_of(b"");
        for &b in b"hunter2" {
            e.new_user_byte(b, &blank);
        }
        assert!(
            e.overlay().is_empty(),
            "predictions must stay hidden until the server confirms it echoes"
        );
    }

    #[test]
    fn confirmed_echo_makes_subsequent_typing_visible() {
        // After the server proves it echoes (one Correct), later typing in the confirmed epoch shows.
        let (mut e, echoed) = confirm_first_keystroke(DisplayPreference::Always, 250.0);
        e.set_local_frame_sent(1);
        e.new_user_byte(b'y', &echoed); // cursor now at (0,1)
        let ov = e.overlay();
        assert_eq!(
            ov.cell(0, 1).map(|c| c.glyph.as_str()),
            Some("y"),
            "typing after confirmation must be visible"
        );
    }

    #[test]
    fn a_slow_link_shows_confirmed_predictions() {
        // Adaptive: an RTT above the engage threshold shows predictions (never underlined now).
        let (mut e, echoed) = confirm_first_keystroke(DisplayPreference::Adaptive, 120.0);
        e.set_local_frame_sent(1);
        e.new_user_byte(b'y', &echoed);
        let ov = e.overlay();
        assert_eq!(ov.cell(0, 1).map(|c| c.glyph.as_str()), Some("y"));
        assert!(!ov.cell(0, 1).unwrap().underline, "predictions are not underlined");
    }

    #[test]
    fn adaptive_engagement_has_hysteresis() {
        let (mut e, echoed) = confirm_first_keystroke(DisplayPreference::Adaptive, 120.0);
        e.set_local_frame_sent(1);
        e.new_user_byte(b'y', &echoed);
        assert!(!e.overlay().is_empty(), "engaged above 60 ms");
        // Between the thresholds the latch holds its state.
        e.set_rtt_ms(50.0);
        assert!(!e.overlay().is_empty(), "still engaged in the hysteresis band");
        // Below the low threshold it disengages and the real echo wins.
        e.set_rtt_ms(30.0);
        assert!(e.overlay().is_empty(), "disengaged below 40 ms");
        // And re-engages only above the high threshold, not within the band.
        e.set_rtt_ms(50.0);
        assert!(e.overlay().is_empty(), "45 ms does not re-engage");
        e.set_rtt_ms(70.0);
        assert!(!e.overlay().is_empty(), "re-engaged above 60 ms");
    }

    #[test]
    fn no_prediction_shown_on_fast_link() {
        // Even after a confirmation, a fast link keeps adaptive engagement off so the real echo wins.
        let (mut e, echoed) = confirm_first_keystroke(DisplayPreference::Adaptive, 5.0);
        e.set_local_frame_sent(1);
        e.new_user_byte(b'y', &echoed);
        assert!(e.overlay().is_empty());
    }

    #[test]
    fn no_echo_keeps_secret_hidden_and_cleans_up() {
        // Password-prompt style: the server never echoes -> never shown, then culled away.
        let mut e = PredictionEngine::new(DisplayPreference::Always);
        e.set_local_frame_sent(0);
        let blank = screen_of(b"");
        e.new_user_byte(b's', &blank);
        assert!(
            e.overlay().is_empty(),
            "non-echoed input is never shown"
        );

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
        e.set_rtt_ms(500.0);
        let screen = screen_of(b"");
        e.new_user_byte(b'x', &screen);
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
        e.new_user_byte(b'X', &screen);
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
        e.new_user_byte(0x7f, &screen); // backspace
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
        // Regression: the unknown-column guard must be overflow-safe on a peer-controlled width.
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
        e.new_user_byte(0x7f, p.screen()); // backspace — must not panic
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
        e.new_user_byte(b'a', &blank);
        let echoed = screen_of(b"a");
        e.set_local_frame_late_acked(1);
        e.cull(&echoed); // confirmed_epoch = 1

        // Type "bc": 'b' on frame 2 (will be confirmed), 'c' on frame 3 (stays pending), so 'c'
        // survives the cull where 'b' confirms — and can be recolored.
        e.set_local_frame_sent(1);
        e.new_user_byte(b'b', &echoed);
        e.set_local_frame_sent(2);
        e.new_user_byte(b'c', &echoed);
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
        let (mut e, echoed) = confirm_first_keystroke(DisplayPreference::Always, 250.0);
        e.set_local_frame_sent(1);
        for &b in b"\x1b[D" {
            e.new_user_byte(b, &echoed); // ESC [ D
        }
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
        let (mut e, echoed) = confirm_first_keystroke(DisplayPreference::Always, 250.0);
        e.set_local_frame_sent(1);
        for &b in b"\x1bOD" {
            e.new_user_byte(b, &echoed); // ESC O D
        }
        assert_eq!(e.overlay().cursor(), Some((0, 0)));
    }

    #[test]
    fn double_width_grapheme_predicted_and_advances_cursor_by_two() {
        // A CJK character is double-width: its multi-byte UTF-8 arrives one byte at a time and is
        // reassembled into a single predicted glyph, with the cursor stepping forward two cells
        // (and no stray glyph in the continuation cell).
        let (mut e, echoed) = confirm_first_keystroke(DisplayPreference::Always, 250.0);
        e.set_local_frame_sent(1);
        for &b in "世".as_bytes() {
            e.new_user_byte(b, &echoed); // cursor seeds from the real screen at (0,1)
        }
        let ov = e.overlay();
        assert_eq!(
            ov.cell(0, 1).map(|c| c.glyph.as_str()),
            Some("世"),
            "the wide grapheme is predicted at the cursor column"
        );
        assert!(
            ov.cell(0, 2).is_none(),
            "the continuation cell of a wide char carries no predicted glyph"
        );
        assert_eq!(
            ov.cursor(),
            Some((0, 3)),
            "cursor advances by two cells for a double-width char"
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
            let (mut e, echoed) = confirm_first_keystroke(DisplayPreference::Always, 250.0);
            e.set_local_frame_sent(1);
            for &b in word.as_bytes() {
                e.new_user_byte(b, &echoed);
            }
            let ov = e.overlay();
            // The first typed char lands at col 1 (cursor seeded from the echoed "x"); the accent
            // is the 3rd char, so column 3.
            assert_eq!(
                ov.cell(0, 3).map(|c| c.glyph.as_str()),
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
}
