//! # rmosh-predict — the local-echo prediction engine
//!
//! What makes typing feel instant on a laggy link. When the user types, the client *guesses*
//! what each keystroke does to the screen and displays it immediately (underlined on high-RTT
//! links), then confirms or corrects when the authoritative server frame arrives. A focused
//! port of mosh's `Overlay::PredictionEngine`.
//!
//! ## Scope of this port
//!
//! The headline behavior — instant echo of ordinary typing, with epoch-gated confirmation
//! driven by the server's debounced **echo-ack** (not the raw network ack), adaptive
//! engagement by SRTT, underline flagging, and emergent password/no-echo suppression — is
//! faithful. It predicts ASCII printables, backspace, CR/LF, the left/right arrow keys, and
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
use vt100::{Color, Screen};

/// Tunable engagement / flagging / glitch thresholds for the predictor (mosh `terminaloverlay.h`
/// values). Lifted out of module constants so a front-end can tune responsiveness and tests can
/// drive engagement deterministically. [`Default`] reproduces the historical hardcoded values, so
/// `PredictionEngine::new` behaves exactly as before.
#[derive(Debug, Clone, Copy)]
pub struct PredictionConfig {
    /// SRTT (ms) at/below which the engagement trigger releases (hysteresis with `srtt_trigger_high`).
    pub srtt_trigger_low: f64,
    /// SRTT (ms) above which predictions begin to show (Adaptive mode).
    pub srtt_trigger_high: f64,
    /// SRTT (ms) at/below which underline flagging stops.
    pub flag_trigger_low: f64,
    /// SRTT (ms) above which shown predictions are underline-flagged.
    pub flag_trigger_high: f64,
    /// A prediction pending at least this long (ms) escalates the glitch trigger.
    pub glitch_threshold_ms: u64,
    /// Glitch-repair counter target (how many fast confirmations cure a glitch).
    pub glitch_repair_count: u32,
    /// Minimum interval (ms) between successive glitch-repair decrements.
    pub glitch_repair_min_interval_ms: u64,
    /// A prediction pending at least this long (ms) forces maximal flagging.
    pub glitch_flag_threshold_ms: u64,
}

impl Default for PredictionConfig {
    fn default() -> Self {
        // mosh terminaloverlay.h defaults.
        PredictionConfig {
            srtt_trigger_low: 20.0,
            srtt_trigger_high: 30.0,
            flag_trigger_low: 50.0,
            flag_trigger_high: 80.0,
            glitch_threshold_ms: 250,
            glitch_repair_count: 10,
            glitch_repair_min_interval_ms: 150,
            glitch_flag_threshold_ms: 5000,
        }
    }
}

/// When predictions are drawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayPreference {
    /// Always render predictions.
    Always,
    /// Never predict (the plain, non-speculative path).
    Never,
    /// Render only when the link is slow enough to benefit (default).
    Adaptive,
}

/// A speculative cell for the renderer to draw on top of the authoritative grid.
#[derive(Clone, Debug)]
pub struct PredictedCell {
    /// The predicted glyph. **Empty when [`unknown`](PredictedCell::unknown)** — the renderer
    /// must then only hint (underline the existing real cell), never overwrite its content.
    pub glyph: String,
    pub fg: Color,
    pub bg: Color,
    /// Whether to underline it (mosh's "flagging" on high-latency links).
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
        Overlay::default()
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
    pub fn len(&self) -> usize {
        self.cells.len()
    }
}

#[derive(Clone)]
struct PredCell {
    expiration_frame: u64,
    tentative_epoch: u64,
    prediction_time: u64,
    glyph: String,
    fg: Color,
    bg: Color,
    /// History of prior contents at this cell so a rewrite that lands back on an earlier value
    /// grades "no credit" (can't falsely confirm an epoch).
    original_contents: Vec<String>,
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

/// The prediction engine. Drive it: [`set_local_frame_sent`](Self::set_local_frame_sent)
/// before feeding typed bytes; [`new_user_byte`](Self::new_user_byte) per typed byte;
/// [`set_local_frame_late_acked`](Self::set_local_frame_late_acked) + [`set_srtt`](Self::set_srtt)
/// + [`cull`](Self::cull) when a server frame arrives; [`overlay`](Self::overlay) to render.
pub struct PredictionEngine {
    pref: DisplayPreference,
    cells: BTreeMap<(u16, u16), PredCell>,
    cursor: Option<PredCursor>,
    prediction_epoch: u64,
    confirmed_epoch: u64,
    local_frame_sent: u64,
    late_acked: u64,
    srtt_ms: f64,
    srtt_trigger: bool,
    glitch_trigger: u32,
    flagging: bool,
    last_quick_confirmation: u64,
    last_size: Option<(u16, u16)>,
    last_byte: u8,
    /// Escape-sequence parser state across raw input bytes (for arrow-key prediction).
    esc: EscState,
    /// Partial UTF-8 sequence accumulated across calls (input arrives one byte at a time), and
    /// the total byte length its leading byte announced. Empty/0 when not mid-grapheme.
    utf8_buf: Vec<u8>,
    utf8_need: usize,
    /// false = insert mode (typing mid-line shifts the row right; backspace shifts left);
    /// true = overwrite mode (single-cell edits). Readline/shells default to insert.
    predict_overwrite: bool,
    /// Tunable engagement / flagging / glitch thresholds (mosh defaults via [`PredictionConfig`]).
    config: PredictionConfig,
}

impl PredictionEngine {
    /// A predictor with the default (mosh) engagement thresholds.
    pub fn new(pref: DisplayPreference) -> Self {
        Self::with_config(pref, PredictionConfig::default())
    }

    /// A predictor with explicit engagement thresholds (for tuning / deterministic tests).
    pub fn with_config(pref: DisplayPreference, config: PredictionConfig) -> Self {
        PredictionEngine {
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
            srtt_ms: 250.0,
            srtt_trigger: false,
            glitch_trigger: 0,
            flagging: false,
            last_quick_confirmation: 0,
            last_size: None,
            last_byte: 0,
            esc: EscState::Ground,
            utf8_buf: Vec::new(),
            utf8_need: 0,
            predict_overwrite: false,
            config,
        }
    }

    /// Read the predicted-or-real glyph + style + unknown-ness at a cell — the source content a
    /// row-shift copies from. Prefers an active prediction over the authoritative screen.
    fn pred_or_real_glyph(
        &self,
        screen: &Screen,
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

    pub fn set_display_preference(&mut self, pref: DisplayPreference) {
        self.pref = pref;
    }
    /// The newest local input frame number sent so far (predictions expire at this + 1).
    pub fn set_local_frame_sent(&mut self, n: u64) {
        self.local_frame_sent = n;
    }
    /// The server's echo-ack: the newest input frame reflected on screen.
    pub fn set_local_frame_late_acked(&mut self, n: u64) {
        self.late_acked = n;
    }
    /// The smoothed RTT (ms) used for adaptive engagement / flagging.
    pub fn set_srtt(&mut self, ms: f64) {
        self.srtt_ms = ms;
    }

    fn become_tentative(&mut self) {
        self.prediction_epoch += 1;
    }

    fn tentative(&self, epoch: u64) -> bool {
        epoch > self.confirmed_epoch
    }

    fn active(&self) -> bool {
        self.cursor.is_some() || !self.cells.is_empty()
    }

    /// Ensure a cursor prediction exists in the current epoch, seeded from the real cursor.
    fn init_cursor(&mut self, screen: &Screen) {
        let (crow, ccol) = screen.cursor_position();
        let need_new = match &self.cursor {
            None => true,
            Some(c) => c.tentative_epoch != self.prediction_epoch,
        };
        if need_new {
            let (row, col) = self
                .cursor
                .as_ref()
                .map(|c| (c.row, c.col))
                .unwrap_or((crow, ccol));
            self.cursor = Some(PredCursor {
                expiration_frame: self.local_frame_sent + 1,
                tentative_epoch: self.prediction_epoch,
                row,
                col,
            });
        }
    }

    fn newline_cr(&mut self, screen: &Screen) {
        let (rows, _) = screen.size();
        self.init_cursor(screen);
        if let Some(c) = self.cursor.as_mut() {
            c.col = 0;
            if c.row + 1 < rows {
                c.row += 1;
            }
            // On the last row we do NOT predict a scroll (mosh deliberately avoids it).
        }
    }

    /// Predict a horizontal cursor move (`dir > 0` = right, `dir < 0` = left), clamped to the
    /// row. Cursor-only prediction in the current epoch, confirmed via `cursor_validity`; like
    /// a typed char it does not open a new epoch. Vertical arrows are not predicted (the caller
    /// `become_tentative`s them).
    fn predict_arrow(&mut self, screen: &Screen, dir: i32) {
        self.init_cursor(screen);
        let exp = self.local_frame_sent + 1;
        let (_, cols) = screen.size();
        if let Some(c) = self.cursor.as_mut() {
            if dir > 0 && c.col + 1 < cols {
                c.col += 1;
                c.expiration_frame = exp;
            } else if dir < 0 && c.col > 0 {
                c.col -= 1;
                c.expiration_frame = exp;
            }
        }
    }

    /// Predict a full UTF-8 grapheme `g` (already decoded from accumulated bytes). Places the
    /// glyph at the cursor and advances by its display width — two cells for CJK/emoji, whose
    /// continuation cell vt100 leaves empty (so we predict nothing there). Zero-width
    /// (combining) graphemes and ones that would land on the wrap-ambiguous right edge fall back
    /// to a tentative epoch. Overwrite-only (no insert-mode tail shift for wide chars — that
    /// rarer case is left to the server's real echo).
    fn predict_wide(&mut self, now: u64, g: &str, screen: &Screen) {
        let w = g.width();
        if w == 0 {
            self.become_tentative(); // combining / zero-width: can't place safely
            return;
        }
        let (_, cols) = screen.size();
        self.init_cursor(screen);
        let (row, col) = {
            let c = self.cursor.as_ref().unwrap();
            (c.row, c.col)
        };
        // Need the whole glyph to fit strictly before the last column (the edge is wrap-ambiguous).
        if col + (w as u16) >= cols {
            self.become_tentative();
            self.init_cursor(screen);
            return;
        }
        let exp = self.local_frame_sent + 1;
        let epoch = self.prediction_epoch;
        let original = cell_glyph(screen, row, col);
        let (fg, bg) = glyph_style(screen, row, col);
        self.cells.insert(
            (row, col),
            PredCell {
                expiration_frame: exp,
                tentative_epoch: epoch,
                prediction_time: now,
                glyph: g.to_string(),
                fg,
                bg,
                original_contents: vec![original],
                unknown: false,
            },
        );
        if let Some(c) = self.cursor.as_mut() {
            c.expiration_frame = exp;
            c.col += w as u16;
        }
    }

    /// Record a typed byte and speculate its on-screen effect against `screen` (the latest
    /// authoritative frame). Validates existing predictions first (`cull`).
    pub fn new_user_byte(&mut self, now: u64, byte: u8, screen: &Screen) {
        if self.pref == DisplayPreference::Never {
            return;
        }
        self.cull(now, screen);

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
                        Some(s) => self.predict_wide(now, &s, screen),
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
                self.init_cursor(screen);
                let col = self.cursor.as_ref().unwrap().col;
                if col + 1 >= cols {
                    // Last column is ambiguous (wrap vs. overwrite); hide until confirmed.
                    self.become_tentative();
                    self.init_cursor(screen);
                }
                let (row, col) = {
                    let c = self.cursor.as_ref().unwrap();
                    (c.row, c.col)
                };
                let exp = self.local_frame_sent + 1;
                let epoch = self.prediction_epoch;
                // Insert mode: shift the row right (cols-1 down to col+1) so the tail moves over
                // to make room — matching what a readline-style line editor will render. Iterate
                // right-to-left so each cell reads its left neighbor's pre-shift content.
                if !self.predict_overwrite {
                    for i in ((col + 1)..cols).rev() {
                        let (g, fg, bg, src_unknown) = self.pred_or_real_glyph(screen, row, i - 1);
                        let original = cell_glyph(screen, row, i);
                        // The rightmost cell takes content pushed off-screen -> unknown.
                        let unknown = i == cols - 1 || src_unknown;
                        self.cells.insert(
                            (row, i),
                            PredCell {
                                expiration_frame: exp,
                                tentative_epoch: epoch,
                                prediction_time: now,
                                glyph: if unknown { String::new() } else { g },
                                fg,
                                bg,
                                original_contents: vec![original],
                                unknown,
                            },
                        );
                    }
                }
                let original = cell_glyph(screen, row, col);
                let (fg, bg) = glyph_style(screen, row, col);
                self.cells.insert(
                    (row, col),
                    PredCell {
                        expiration_frame: exp,
                        tentative_epoch: epoch,
                        prediction_time: now,
                        glyph: (byte as char).to_string(),
                        fg,
                        bg,
                        original_contents: vec![original],
                        unknown: false,
                    },
                );
                if let Some(c) = self.cursor.as_mut() {
                    c.expiration_frame = self.local_frame_sent + 1;
                    if c.col + 1 < cols {
                        c.col += 1;
                    } else {
                        self.become_tentative();
                        self.newline_cr(screen);
                    }
                }
            }
            0x7f | 0x08 => {
                // Backspace: step the cursor back one column.
                self.init_cursor(screen);
                let (row, col, do_pred) = {
                    let c = self.cursor.as_mut().unwrap();
                    if c.col > 0 {
                        c.col -= 1;
                        c.expiration_frame = self.local_frame_sent + 1;
                        (c.row, c.col, true)
                    } else {
                        (c.row, c.col, false)
                    }
                };
                if do_pred {
                    let exp = self.local_frame_sent + 1;
                    let epoch = self.prediction_epoch;
                    if self.predict_overwrite {
                        // Overwrite mode: just blank the cell at the new cursor position.
                        let original = cell_glyph(screen, row, col);
                        self.cells.insert(
                            (row, col),
                            PredCell {
                                expiration_frame: exp,
                                tentative_epoch: epoch,
                                prediction_time: now,
                                glyph: " ".to_string(),
                                fg: Color::Default,
                                bg: Color::Default,
                                original_contents: vec![original],
                                unknown: false,
                            },
                        );
                    } else {
                        // Insert mode: shift the row left from col to the right edge; the far
                        // right column gains whatever was off-screen -> unknown (underline hint,
                        // never a guessed glyph). Left-to-right so each cell reads its unshifted
                        // right neighbor.
                        for i in col..cols {
                            let original = cell_glyph(screen, row, i);
                            let (g, fg, bg, unknown) = if i + 1 < cols {
                                self.pred_or_real_glyph(screen, row, i + 1)
                            } else {
                                (String::new(), Color::Default, Color::Default, true)
                            };
                            self.cells.insert(
                                (row, i),
                                PredCell {
                                    expiration_frame: exp,
                                    tentative_epoch: epoch,
                                    prediction_time: now,
                                    glyph: if unknown { String::new() } else { g },
                                    fg,
                                    bg,
                                    original_contents: vec![original],
                                    unknown,
                                },
                            );
                        }
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

    /// Validate predictions against the freshly-arrived authoritative `screen`.
    pub fn cull(&mut self, now: u64, screen: &Screen) {
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

        // SRTT trigger (show predictions) with hysteresis.
        if self.srtt_ms > self.config.srtt_trigger_high {
            self.srtt_trigger = true;
        } else if self.srtt_trigger
            && self.srtt_ms <= self.config.srtt_trigger_low
            && !self.active()
        {
            self.srtt_trigger = false;
        }
        // Flagging (underline) with hysteresis.
        if self.srtt_ms > self.config.flag_trigger_high {
            self.flagging = true;
        } else if self.srtt_ms <= self.config.flag_trigger_low {
            self.flagging = false;
        }
        if self.glitch_trigger > self.config.glitch_repair_count {
            self.flagging = true;
        }

        let late = self.late_acked;
        let confirmed = self.confirmed_epoch;

        let mut to_remove: Vec<(u16, u16)> = Vec::new();
        let mut kill_epochs: BTreeSet<u64> = BTreeSet::new();
        let mut kill_all = false;
        let mut max_confirm = confirmed;
        let mut new_glitch = self.glitch_trigger;
        let mut last_quick = self.last_quick_confirmation;

        for (&(row, col), cell) in self.cells.iter() {
            let v = cell_validity(cell, screen, row, col, rows, cols, late);
            match v {
                Validity::Pending => {
                    // Long-pending predictions escalate visibility (glitch).
                    let age = now.saturating_sub(cell.prediction_time);
                    if age >= self.config.glitch_flag_threshold_ms {
                        new_glitch = self.config.glitch_repair_count * 2;
                    } else if age >= self.config.glitch_threshold_ms
                        && new_glitch < self.config.glitch_repair_count
                    {
                        new_glitch = self.config.glitch_repair_count;
                    }
                }
                Validity::Correct => {
                    if cell.tentative_epoch > max_confirm {
                        max_confirm = cell.tentative_epoch;
                    }
                    // Reward fast confirmations: cure the glitch trigger gradually.
                    if now.saturating_sub(cell.prediction_time) < self.config.glitch_threshold_ms
                        && new_glitch > 0
                        && now.saturating_sub(self.config.glitch_repair_min_interval_ms)
                            >= last_quick
                    {
                        new_glitch -= 1;
                        last_quick = now;
                    }
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
        self.glitch_trigger = new_glitch;
        self.last_quick_confirmation = last_quick;
        for k in &to_remove {
            self.cells.remove(k);
        }
        if !kill_epochs.is_empty() {
            self.cells
                .retain(|_, c| !kill_epochs.contains(&c.tentative_epoch));
            self.become_tentative();
        }

        // Cursor validation.
        if let Some(c) = &self.cursor {
            let cv = cursor_validity(c, screen, late);
            match cv {
                Validity::IncorrectOrExpired => {
                    self.reset();
                }
                Validity::Pending => {}
                _ => {
                    self.cursor = None; // resolved
                }
            }
        }
    }

    /// Build the render overlay for the current frame, honoring the display policy and epoch
    /// gating. Empty when nothing should be shown.
    pub fn overlay(&self, screen: &Screen) -> Overlay {
        let show = match self.pref {
            DisplayPreference::Never => false,
            DisplayPreference::Always => true,
            DisplayPreference::Adaptive => self.srtt_trigger || self.glitch_trigger > 0,
        };
        if !show {
            return Overlay::empty();
        }
        let (_, cols) = screen.size();
        let mut ov = Overlay::empty();
        for (&(row, col), cell) in self.cells.iter() {
            if self.tentative(cell.tentative_epoch) {
                continue; // hidden until its epoch is confirmed
            }
            if cell.unknown {
                // "Something changed here, not sure what": only hint with an underline (and
                // only when flagging, and not in the always-ambiguous last column). Never push
                // a glyph — the renderer underlines the real cell instead of overwriting it.
                if self.flagging && col != cols.saturating_sub(1) {
                    ov.cells.insert(
                        (row, col),
                        PredictedCell {
                            glyph: String::new(),
                            fg: Color::Default,
                            bg: Color::Default,
                            underline: true,
                            unknown: true,
                        },
                    );
                }
                continue;
            }
            ov.cells.insert(
                (row, col),
                PredictedCell {
                    glyph: cell.glyph.clone(),
                    fg: cell.fg,
                    bg: cell.bg,
                    underline: self.flagging,
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
        self.become_tentative();
    }
}

fn cell_glyph(screen: &Screen, row: u16, col: u16) -> String {
    screen
        .cell(row, col)
        .filter(|c| c.has_contents())
        .map(|c| c.contents().to_string())
        .unwrap_or_default()
}

fn glyph_style(screen: &Screen, row: u16, col: u16) -> (Color, Color) {
    // Copy the style of the neighbor to the left if it has content; else terminal default.
    if col > 0 {
        if let Some(c) = screen.cell(row, col - 1) {
            if c.has_contents() {
                return (c.fgcolor(), c.bgcolor());
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
    screen: &Screen,
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
        if cell.original_contents.iter().any(|o| o == &actual) {
            Validity::CorrectNoCredit // it already looked like this earlier; no credit
        } else {
            Validity::Correct
        }
    } else {
        Validity::IncorrectOrExpired
    }
}

fn cursor_validity(cur: &PredCursor, screen: &Screen, late_acked: u64) -> Validity {
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

    fn screen_of(bytes: &[u8]) -> Screen {
        let mut p = vt100::Parser::new(24, 80, 0);
        p.process(bytes);
        p.screen().clone()
    }

    /// Drive a confirmation round: type `first` (hidden), have the server echo it on `echoed`
    /// and ack frame 1, cull (advancing `confirmed_epoch`). Returns the engine ready for
    /// subsequent typing to be *visible*.
    fn confirm_first_keystroke(pref: DisplayPreference, srtt: f64) -> (PredictionEngine, Screen) {
        let mut e = PredictionEngine::new(pref);
        e.set_srtt(srtt);
        e.set_local_frame_sent(0);
        let blank = screen_of(b"");
        e.new_user_byte(100, b'x', &blank);
        assert!(
            e.overlay(&blank).is_empty(),
            "the very first keystroke must be hidden until the server confirms it echoes"
        );
        let echoed = screen_of(b"x");
        e.set_local_frame_late_acked(1);
        e.cull(200, &echoed); // grades 'x' Correct -> confirmed_epoch = 1
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
            e.new_user_byte(100, b, &blank);
        }
        assert!(
            e.overlay(&blank).is_empty(),
            "predictions must stay hidden until the server confirms it echoes"
        );
    }

    #[test]
    fn confirmed_echo_makes_subsequent_typing_visible() {
        // After the server proves it echoes (one Correct), later typing in the confirmed epoch shows.
        let (mut e, echoed) = confirm_first_keystroke(DisplayPreference::Always, 250.0);
        e.set_local_frame_sent(1);
        e.new_user_byte(300, b'y', &echoed); // cursor now at (0,1)
        let ov = e.overlay(&echoed);
        assert_eq!(
            ov.cell(0, 1).map(|c| c.glyph.as_str()),
            Some("y"),
            "typing after confirmation must be visible"
        );
    }

    #[test]
    fn slow_link_flags_confirmed_predictions() {
        let (mut e, echoed) = confirm_first_keystroke(DisplayPreference::Adaptive, 120.0);
        e.set_local_frame_sent(1);
        e.new_user_byte(300, b'y', &echoed);
        let ov = e.overlay(&echoed);
        assert_eq!(ov.cell(0, 1).map(|c| c.glyph.as_str()), Some("y"));
        assert!(
            ov.cell(0, 1).unwrap().underline,
            "slow link should flag predictions"
        );
    }

    #[test]
    fn injected_srtt_threshold_gates_engagement_deterministically() {
        // Adaptive mode shows predictions only when srtt_ms > config.srtt_trigger_high. With an
        // injected threshold far above the link's SRTT, a confirmed keystroke stays hidden; with
        // a threshold below it, the same keystroke engages. Only testable now that the trigger is
        // injectable (it used to be a hardcoded const).
        fn confirm_then_type_visible(cfg: PredictionConfig, srtt: f64) -> bool {
            let mut e = PredictionEngine::with_config(DisplayPreference::Adaptive, cfg);
            e.set_srtt(srtt);
            e.set_local_frame_sent(0);
            let blank = screen_of(b"");
            e.new_user_byte(100, b'x', &blank);
            let echoed = screen_of(b"x");
            e.set_local_frame_late_acked(1);
            e.cull(200, &echoed); // confirm epoch 1
            e.set_local_frame_sent(1);
            e.new_user_byte(300, b'y', &echoed);
            !e.overlay(&echoed).is_empty()
        }
        let high = PredictionConfig {
            srtt_trigger_high: 1_000.0,
            srtt_trigger_low: 999.0,
            ..Default::default()
        };
        assert!(
            !confirm_then_type_visible(high, 120.0),
            "srtt 120 below the injected 1000ms engage threshold -> predictions hidden"
        );
        let low = PredictionConfig {
            srtt_trigger_high: 10.0,
            srtt_trigger_low: 5.0,
            ..Default::default()
        };
        assert!(
            confirm_then_type_visible(low, 120.0),
            "srtt 120 above the injected 10ms engage threshold -> predictions shown"
        );
    }

    #[test]
    fn no_prediction_shown_on_fast_link() {
        // Even after a confirmation, a fast link keeps the SRTT gate closed so the real echo wins.
        let (mut e, echoed) = confirm_first_keystroke(DisplayPreference::Adaptive, 5.0);
        e.set_local_frame_sent(1);
        e.new_user_byte(300, b'y', &echoed);
        assert!(e.overlay(&echoed).is_empty());
    }

    #[test]
    fn no_echo_keeps_secret_hidden_and_cleans_up() {
        // Password-prompt style: the server never echoes -> never shown, then culled away.
        let mut e = PredictionEngine::new(DisplayPreference::Always);
        e.set_local_frame_sent(0);
        let blank = screen_of(b"");
        e.new_user_byte(100, b's', &blank);
        assert!(
            e.overlay(&blank).is_empty(),
            "non-echoed input is never shown"
        );

        let still_blank = screen_of(b"");
        e.set_local_frame_late_acked(1);
        e.cull(200, &still_blank);
        assert!(
            e.overlay(&still_blank).is_empty(),
            "non-echoed input must not leave a predicted glyph"
        );
    }

    #[test]
    fn never_mode_predicts_nothing() {
        let mut e = PredictionEngine::new(DisplayPreference::Never);
        e.set_srtt(500.0);
        let screen = screen_of(b"");
        e.new_user_byte(100, b'x', &screen);
        assert!(e.overlay(&screen).is_empty());
    }

    #[test]
    fn insert_mode_shifts_row_right() {
        // Screen "ab" with the cursor on 'b' (col 1). Typing 'X' should INSERT before 'b',
        // shifting the tail right — not overwrite 'b'. (Inspect predicted cells directly; the
        // epoch gate hides them from overlay() until confirmed, but the shift populates cells.)
        let mut e = PredictionEngine::new(DisplayPreference::Always);
        e.set_local_frame_sent(0);
        let screen = screen_of(b"ab\x1b[1;2H"); // cursor -> row1 col2 = (0,1)
        e.new_user_byte(0, b'X', &screen);
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
        // and the far-right column becomes unknown (content scrolled in from off-screen).
        let mut e = PredictionEngine::new(DisplayPreference::Always);
        e.set_local_frame_sent(0);
        let screen = screen_of(b"abc\x1b[1;3H"); // cursor -> (0,2)
        e.new_user_byte(0, 0x7f, &screen); // backspace
        let (_, cols) = screen.size();
        assert_eq!(
            e.cells.get(&(0, 1)).map(|c| c.glyph.as_str()),
            Some("c"),
            "tail shifted left"
        );
        assert!(
            e.cells
                .get(&(0, cols - 1))
                .map(|c| c.unknown)
                .unwrap_or(false),
            "right edge is marked unknown after a mid-line backspace"
        );
    }

    #[test]
    fn unknown_cell_overlay_is_underline_hint_only() {
        // An unknown cell, when flagging, renders as an underline-only hint: empty glyph (so the
        // renderer underlines the real cell instead of overwriting it), unknown = true.
        let mut e = PredictionEngine::new(DisplayPreference::Always);
        e.flagging = true;
        e.confirmed_epoch = 5; // un-gate the cell below (tentative_epoch 1 <= 5)
        e.cells.insert(
            (0, 1),
            PredCell {
                expiration_frame: 0,
                tentative_epoch: 1,
                prediction_time: 0,
                glyph: String::new(),
                fg: Color::Default,
                bg: Color::Default,
                original_contents: Vec::new(),
                unknown: true,
            },
        );
        let screen = screen_of(b"");
        let ov = e.overlay(&screen);
        let c = ov.cell(0, 1).expect("unknown hint should be present");
        assert!(c.unknown && c.underline && c.glyph.is_empty());
    }

    #[test]
    fn left_arrow_predicts_cursor_and_leaves_no_glyph() {
        // After confirming a keystroke (cursor at (0,1)), a left arrow predicts the cursor one
        // column left and must NOT leave literal '[' / 'D' glyphs from the escape bytes.
        let (mut e, echoed) = confirm_first_keystroke(DisplayPreference::Always, 250.0);
        e.set_local_frame_sent(1);
        for &b in b"\x1b[D" {
            e.new_user_byte(300, b, &echoed); // ESC [ D
        }
        let ov = e.overlay(&echoed);
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
            e.new_user_byte(300, b, &echoed); // ESC O D
        }
        assert_eq!(e.overlay(&echoed).cursor(), Some((0, 0)));
    }

    #[test]
    fn double_width_grapheme_predicted_and_advances_cursor_by_two() {
        // A CJK character is double-width: its multi-byte UTF-8 arrives one byte at a time and is
        // reassembled into a single predicted glyph, with the cursor stepping forward two cells
        // (and no stray glyph in the continuation cell).
        let (mut e, echoed) = confirm_first_keystroke(DisplayPreference::Always, 250.0);
        e.set_local_frame_sent(1);
        for &b in "世".as_bytes() {
            e.new_user_byte(300, b, &echoed); // cursor seeds from the real screen at (0,1)
        }
        let ov = e.overlay(&echoed);
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
        // it). moshers2 reassembles the whole UTF-8 grapheme before predicting, so the predicted
        // glyph is always the real character. (`)` is the meaningful char-level artifact; ü's raw
        // 0xFC can't even exist in a Rust `String`, so reassembly itself is the guarantee.)
        for (word, accent) in [("glück", "ü"), ("faĩl", "ĩ")] {
            let (mut e, echoed) = confirm_first_keystroke(DisplayPreference::Always, 250.0);
            e.set_local_frame_sent(1);
            for &b in word.as_bytes() {
                e.new_user_byte(300, b, &echoed);
            }
            let ov = e.overlay(&echoed);
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
