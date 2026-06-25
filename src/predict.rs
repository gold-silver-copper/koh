//! # koh-predict — the local-echo prediction engine
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
/// values).
///
/// Lifted out of module constants so a front-end can tune responsiveness and tests can
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
        Self {
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

/// The prediction engine.
///
/// Drive it: [`set_local_frame_sent`](Self::set_local_frame_sent)
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

    /// Insert a prediction cell at `(row, col)`, stamping the shared, load-bearing invariant: the
    /// expiration frame (`local_frame_sent + 1`), the current `prediction_epoch` (the security gate
    /// that hides input until the server confirms it echoes), `now`, and a one-element
    /// `original_contents` snapshot of the cell being overwritten (so a rewrite back to an earlier
    /// value grades "no credit"). Centralizes the five identical literals so a future edit can't
    /// drift one site's invariant on this security-sensitive path (S-07). The per-cell fields
    /// (`glyph`/`fg`/`bg`/`unknown`) vary and are passed in.
    #[expect(
        clippy::too_many_arguments,
        reason = "the per-cell fields differ across the five sites; the invariant fields are stamped here"
    )]
    fn place_cell(
        &mut self,
        screen: &Screen,
        row: u16,
        col: u16,
        glyph: String,
        fg: Color,
        bg: Color,
        unknown: bool,
        now: u64,
    ) {
        self.cells.insert(
            (row, col),
            PredCell {
                expiration_frame: self.local_frame_sent + 1,
                tentative_epoch: self.prediction_epoch,
                prediction_time: now,
                glyph,
                fg,
                bg,
                original_contents: vec![cell_glyph(screen, row, col)],
                unknown,
            },
        );
    }

    /// Choose insert-mode (default, `false`) vs overwrite-mode (`true`) prediction. In overwrite
    /// mode a typed glyph replaces the cell under the cursor instead of shifting the tail right —
    /// the correct behavior for full-screen apps. Mirrors mosh's `$MOSH_PREDICTION_OVERWRITE`.
    pub fn set_predict_overwrite(&mut self, on: bool) {
        self.predict_overwrite = on;
    }
    /// The newest epoch the server has confirmed echoes (predictions at or below it may show).
    /// The confirmation epoch — bumped by [`cull`](Self::cull) when a prediction is confirmed.
    /// Read by the client status line (and tests) to surface prediction activity.
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
                .map_or((crow, ccol), |c| (c.row, c.col));
            self.cursor = Some(PredCursor {
                expiration_frame: self.local_frame_sent + 1,
                tentative_epoch: self.prediction_epoch,
                row,
                col,
            });
        }
    }

    /// The predicted cursor, which [`init_cursor`](Self::init_cursor) has just guaranteed is
    /// present. Only call immediately after `init_cursor`.
    #[expect(
        clippy::unwrap_used,
        reason = "init_cursor just set self.cursor to Some"
    )]
    fn cursor_after_init(&self) -> &PredCursor {
        self.cursor.as_ref().unwrap()
    }

    /// The predicted cursor (mutable), which [`init_cursor`](Self::init_cursor) has just
    /// guaranteed is present. Only call immediately after `init_cursor`.
    #[expect(
        clippy::unwrap_used,
        reason = "init_cursor just set self.cursor to Some"
    )]
    fn cursor_after_init_mut(&mut self) -> &mut PredCursor {
        self.cursor.as_mut().unwrap()
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
            let c = self.cursor_after_init();
            (c.row, c.col)
        };
        // Need the whole glyph to fit strictly before the last column (the edge is wrap-ambiguous).
        // Written as `w >= cols - col` (saturating) to avoid a latent `col + w` u16 overflow, matching
        // the hardened backspace path; in production `col, w` are clamped well below u16::MAX anyway.
        if w as u16 >= cols.saturating_sub(col) {
            self.become_tentative();
            self.init_cursor(screen);
            return;
        }
        let exp = self.local_frame_sent + 1;
        let (fg, bg) = glyph_style(screen, row, col);
        self.place_cell(screen, row, col, g.to_string(), fg, bg, false, now);
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
                let col = self.cursor_after_init().col;
                if col + 1 >= cols {
                    // Last column is ambiguous (wrap vs. overwrite); hide until confirmed.
                    self.become_tentative();
                    self.init_cursor(screen);
                }
                let (row, col) = {
                    let c = self.cursor_after_init();
                    (c.row, c.col)
                };
                // Insert mode: shift the row right (cols-1 down to col+1) so the tail moves over
                // to make room — matching what a readline-style line editor will render. Iterate
                // right-to-left so each cell reads its left neighbor's pre-shift content.
                if !self.predict_overwrite {
                    for i in ((col + 1)..cols).rev() {
                        let (g, fg, bg, src_unknown) = self.pred_or_real_glyph(screen, row, i - 1);
                        // The rightmost cell takes content pushed off-screen -> unknown.
                        let unknown = i == cols - 1 || src_unknown;
                        let glyph = if unknown { String::new() } else { g };
                        self.place_cell(screen, row, i, glyph, fg, bg, unknown, now);
                    }
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
                    now,
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
                let exp = self.local_frame_sent + 1;
                let (row, col, do_pred) = {
                    let c = self.cursor_after_init_mut();
                    if c.col > 0 {
                        c.col -= 1;
                        c.expiration_frame = exp;
                        (c.row, c.col, true)
                    } else {
                        (c.row, c.col, false)
                    }
                };
                if do_pred {
                    if self.predict_overwrite {
                        // Overwrite mode: just blank the cell at the new cursor position.
                        self.place_cell(
                            screen,
                            row,
                            col,
                            " ".to_string(),
                            Color::Default,
                            Color::Default,
                            false,
                            now,
                        );
                    } else {
                        // Insert mode: shift the row left from col to the right edge; the last
                        // TWO columns gain whatever was off-screen -> unknown (underline hint,
                        // never a guessed glyph). mosh marks the cell unknown when `i + 2 >= width`
                        // (terminaloverlay.cc), one column wider than the naive "only the last
                        // column" — the right-edge cell a wide grapheme could straddle is ambiguous
                        // too. Left-to-right so each cell reads its unshifted right neighbor.
                        for i in col..cols {
                            // `i < cols - 2` is mosh's `i + 2 < width`, written to never overflow
                            // u16 (the screen width is peer-controlled; `i + 2` would wrap/panic at
                            // cols == u16::MAX). The true branch then has `i + 1 < cols`, so the
                            // `i + 1` read below is in bounds.
                            let (g, fg, bg, unknown) = if i < cols.saturating_sub(2) {
                                self.pred_or_real_glyph(screen, row, i + 1)
                            } else {
                                (String::new(), Color::Default, Color::Default, true)
                            };
                            let glyph = if unknown { String::new() } else { g };
                            self.place_cell(screen, row, i, glyph, fg, bg, unknown, now);
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
    /// Re-evaluate prediction visibility at `now` against the (unchanged) authoritative `screen`,
    /// so a long-pending prediction escalates to the glitch underline on time even on a silent
    /// link. Returns whether the displayed flagging changed (the caller repaints if so).
    ///
    /// The age-based escalation otherwise only runs inside [`cull`](Self::cull) (on a datagram) or
    /// [`new_user_byte`](Self::new_user_byte) (on a keystroke); on a quiet slow link it would not
    /// fire until the next such event. The client loop wakes at least every 50ms, so calling this
    /// keeps the escalation timely (mirrors mosh's `OverlayManager::wait_time`-driven update). It
    /// delegates to `cull`, which is idempotent on an unchanged screen (correct predictions were
    /// already confirmed/removed by the prior datagram), so the only effect here is re-timing.
    pub fn tick(&mut self, now: u64, screen: &Screen) -> bool {
        if self.pref == DisplayPreference::Never || self.cells.is_empty() {
            return false;
        }
        let before = (self.flagging, self.glitch_trigger);
        self.cull(now, screen);
        before != (self.flagging, self.glitch_trigger)
    }

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
        // mosh's "match rest of row to the actual renditions": each `(row, from_col, fg, bg)` run
        // recolors the still-pending predicted cells from `from_col` to the row's end with a freshly
        // confirmed cell's *actual* colors, so they don't flash a guessed rendition before their own
        // frame lands. Applied after the validity pass (can't mutate `cells` while iterating it).
        let mut rendition_runs: Vec<(u16, u16, Color, Color)> = Vec::new();

        for (&(row, col), cell) in &self.cells {
            let v = cell_validity(cell, screen, row, col, rows, cols, late);
            match v {
                Validity::Pending => {
                    // Long-pending predictions escalate visibility (glitch).
                    let age = now.saturating_sub(cell.prediction_time);
                    if age >= self.config.glitch_flag_threshold_ms {
                        new_glitch = self.config.glitch_repair_count.saturating_mul(2);
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
                    // Re-color the rest of this row's pending predictions to the actual confirmed
                    // renditions (mosh terminaloverlay.cc): koh's `PredCell` carries only fg/bg, so
                    // this ports the color/attr-flicker fix to the extent the cell model allows.
                    let (afg, abg) = screen
                        .cell(row, col)
                        .map_or((Color::Default, Color::Default), |c| {
                            (c.fgcolor(), c.bgcolor())
                        });
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
        self.glitch_trigger = new_glitch;
        self.last_quick_confirmation = last_quick;
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
                expiration_frame: self.local_frame_sent + 1,
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
        for (&(row, col), cell) in &self.cells {
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

    #[test]
    fn predict_overwrite_setter_is_honored_and_branch_runs() {
        // The field was previously hardcoded false (the overwrite branch was dead code). The setter
        // must flip it, and predicting in overwrite mode must execute the branch without panicking.
        let mut pe = PredictionEngine::new(DisplayPreference::Always);
        assert!(!pe.predict_overwrite, "default is insert mode");
        pe.set_predict_overwrite(true);
        assert!(pe.predict_overwrite, "setter enables overwrite mode");

        pe.set_local_frame_sent(0);
        let echoed = screen_of(b"abc");
        pe.new_user_byte(0, b'Z', &echoed); // drives the overwrite-mode prediction path
        let _ = pe.overlay(&echoed);
    }

    #[test]
    fn malformed_utf8_midgrapheme_resets_without_panicking() {
        // A lead byte announcing a multi-byte grapheme followed by a NON-continuation byte must
        // reset the UTF-8 accumulator (no concrete prediction, fall back to the server's echo) and
        // must never panic or mis-draw the bytes as literal glyphs.
        let mut pe = PredictionEngine::new(DisplayPreference::Always);
        pe.set_local_frame_sent(0);
        let screen = screen_of(b"");
        pe.new_user_byte(0, 0xE4, &screen); // lead byte of a 3-byte sequence
        pe.new_user_byte(0, b'A', &screen); // not a continuation -> reset
        assert!(
            pe.utf8_buf.is_empty(),
            "the UTF-8 accumulator must reset after a malformed sequence"
        );
        let _ = pe.overlay(&screen);
    }

    #[test]
    fn wide_grapheme_in_overwrite_mode_runs_without_panicking() {
        // The overwrite branch fed a double-width (CJK) grapheme — previously dead code, and the
        // existing overwrite test drives only ASCII, never the wide-char arm.
        let (mut e, screen) = confirm_first_keystroke(DisplayPreference::Always, 250.0);
        e.set_predict_overwrite(true);
        e.set_local_frame_sent(1);
        for &b in "世".as_bytes() {
            e.new_user_byte(300, b, &screen);
        }
        let _ = e.overlay(&screen);
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
            let mut pe = PredictionEngine::new(DisplayPreference::Always);
            pe.set_local_frame_sent(0);
            let screen = screen_of(b"ready prompt $ ");
            let mut now = 0u64;
            for b in &bytes {
                pe.new_user_byte(now, *b, &screen); // must not panic on any byte sequence
                now = now.saturating_add(1);
                proptest::prop_assert!(
                    pe.utf8_buf.len() <= 4,
                    "UTF-8 accumulator grew past 4 bytes: {}",
                    pe.utf8_buf.len()
                );
            }
            let _ = pe.overlay(&screen); // must not panic on the accumulated prediction set
        }
    }

    #[test]
    fn tick_escalates_a_long_pending_prediction_without_a_datagram() {
        let mut pe = PredictionEngine::new(DisplayPreference::Always);
        // A *fast* link, so SRTT-based flagging is off and we isolate the time-based glitch
        // escalation (the thing tick() exists to drive on a silent link).
        pe.set_srtt(0.0);
        pe.set_local_frame_sent(0);
        let blank = screen_of(b"");
        pe.new_user_byte(0, b'a', &blank); // hidden (epoch 1)
        let echoed = screen_of(b"a");
        pe.set_local_frame_late_acked(1);
        pe.cull(50, &echoed); // confirm epoch 1 -> later predictions are shown
        pe.set_local_frame_sent(1);
        pe.new_user_byte(100, b'Z', &echoed); // shown, still-unconfirmed prediction
        assert!(!pe.flagging, "not flagged on a fast link before escalation");
        let before_glitch = pe.glitch_trigger;

        // The server goes silent (no new datagram); only the loop ticks against the same screen.
        // Past the glitch-flag threshold the long-pending prediction escalates the glitch trigger;
        // the trigger turns on flagging (the underline) on the following tick (cull computes
        // flagging from the glitch value *before* re-escalating it — true of the original code too,
        // so the escalation lands within ~2 ticks ≈ 100ms instead of waiting for a datagram).
        let t1 = 100 + pe.config.glitch_flag_threshold_ms + 1;
        let c1 = pe.tick(t1, &echoed);
        assert!(
            pe.glitch_trigger > before_glitch,
            "glitch escalated by age on a silent tick: {before_glitch} -> {}",
            pe.glitch_trigger
        );
        assert!(c1, "tick reports the glitch change so the loop repaints");

        let c2 = pe.tick(t1 + 1, &echoed);
        assert!(
            pe.flagging,
            "the escalated glitch turns on the underline on the next tick"
        );
        assert!(c2, "tick reports the flagging change so the loop repaints");
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
        // and the last TWO columns become unknown (content scrolled in from off-screen; mosh marks
        // the cell unknown when `i + 2 >= width`, so both edge columns, not just the last one).
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
        let p = vt100::Parser::new(1, u16::MAX, 0);
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
        e.new_user_byte(0, 0x7f, p.screen()); // backspace — must not panic
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
        e.new_user_byte(0, b'a', &blank);
        let echoed = screen_of(b"a");
        e.set_local_frame_late_acked(1);
        e.cull(50, &echoed); // confirmed_epoch = 1

        // Type "bc": 'b' on frame 2 (will be confirmed), 'c' on frame 3 (stays pending), so 'c'
        // survives the cull where 'b' confirms — and can be recolored.
        e.set_local_frame_sent(1);
        e.new_user_byte(60, b'b', &echoed);
        e.set_local_frame_sent(2);
        e.new_user_byte(61, b'c', &echoed);
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
        e.cull(70, &colored);
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
                prediction_time: 0,
                glyph: "Q".to_string(),
                fg: Color::Default,
                bg: Color::Default,
                original_contents: vec![String::new()],
                unknown: false,
            },
        );
        let blank = screen_of(b"");
        assert_eq!(
            e.overlay(&blank).cursor(),
            Some((0, 9)),
            "the stale confirmed cursor is drawn before the kill"
        );
        // The frame has no 'Q' at (0,3) -> epoch 2 is killed; the real cursor is at (0,0).
        e.cull(10, &blank);
        assert!(
            e.overlay(&blank).cursor().is_none(),
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
        // it). koh reassembles the whole UTF-8 grapheme before predicting, so the predicted
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
