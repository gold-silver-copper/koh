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
//! faithful. To stay tractable it predicts in **overwrite** mode and only for ASCII
//! printables, backspace, and CR/LF; control/escape/CSI bytes and non-ASCII (wide/emoji)
//! input open a fresh epoch but make no concrete prediction (they fall back to the server's
//! real echo). This never corrupts the display — a wrong or unconfirmed guess is reconciled
//! away — it just doesn't *speed up* those rarer cases.
//!
//! The render-facing output is an [`Overlay`]: the cells to draw speculatively and the
//! predicted cursor position. It is empty whenever the display policy says "don't show."

use std::collections::{BTreeMap, BTreeSet};

use vt100::{Color, Screen};

// --- constants (mosh terminaloverlay.h, milliseconds / counts) ---
const SRTT_TRIGGER_LOW: f64 = 20.0;
const SRTT_TRIGGER_HIGH: f64 = 30.0;
const FLAG_TRIGGER_LOW: f64 = 50.0;
const FLAG_TRIGGER_HIGH: f64 = 80.0;
const GLITCH_THRESHOLD: u64 = 250;
const GLITCH_REPAIR_COUNT: u32 = 10;
const GLITCH_REPAIR_MININTERVAL: u64 = 150;
const GLITCH_FLAG_THRESHOLD: u64 = 5000;

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
    pub glyph: String,
    pub fg: Color,
    pub bg: Color,
    /// Whether to underline it (mosh's "flagging" on high-latency links).
    pub underline: bool,
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
    /// What was there before, so an unchanged cell grades "no credit" (can't falsely confirm).
    original: String,
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
}

impl PredictionEngine {
    pub fn new(pref: DisplayPreference) -> Self {
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
                let original = cell_glyph(screen, row, col);
                let (fg, bg) = glyph_style(screen, row, col);
                self.cells.insert(
                    (row, col),
                    PredCell {
                        expiration_frame: self.local_frame_sent + 1,
                        tentative_epoch: self.prediction_epoch,
                        prediction_time: now,
                        glyph: (byte as char).to_string(),
                        fg,
                        bg,
                        original,
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
                // Backspace (overwrite/erase mode): step back and blank the cell.
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
                    let original = cell_glyph(screen, row, col);
                    self.cells.insert(
                        (row, col),
                        PredCell {
                            expiration_frame: self.local_frame_sent + 1,
                            tentative_epoch: self.prediction_epoch,
                            prediction_time: now,
                            glyph: " ".to_string(),
                            fg: Color::Default,
                            bg: Color::Default,
                            original,
                        },
                    );
                }
            }
            0x0d | 0x0a => {
                // CR/LF: can't predict scroll cleanly — open a new epoch and move the cursor.
                self.become_tentative();
                self.newline_cr(screen);
            }
            _ => {
                // Control / ESC / CSI / non-ASCII: open a new epoch, predict nothing concrete.
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
        if self.srtt_ms > SRTT_TRIGGER_HIGH {
            self.srtt_trigger = true;
        } else if self.srtt_trigger && self.srtt_ms <= SRTT_TRIGGER_LOW && !self.active() {
            self.srtt_trigger = false;
        }
        // Flagging (underline) with hysteresis.
        if self.srtt_ms > FLAG_TRIGGER_HIGH {
            self.flagging = true;
        } else if self.srtt_ms <= FLAG_TRIGGER_LOW {
            self.flagging = false;
        }
        if self.glitch_trigger > GLITCH_REPAIR_COUNT {
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
                    if age >= GLITCH_FLAG_THRESHOLD {
                        new_glitch = GLITCH_REPAIR_COUNT * 2;
                    } else if age >= GLITCH_THRESHOLD && new_glitch < GLITCH_REPAIR_COUNT {
                        new_glitch = GLITCH_REPAIR_COUNT;
                    }
                }
                Validity::Correct => {
                    if cell.tentative_epoch > max_confirm {
                        max_confirm = cell.tentative_epoch;
                    }
                    // Reward fast confirmations: cure the glitch trigger gradually.
                    if now.saturating_sub(cell.prediction_time) < GLITCH_THRESHOLD
                        && new_glitch > 0
                        && now.saturating_sub(GLITCH_REPAIR_MININTERVAL) >= last_quick
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
    pub fn overlay(&self, _screen: &Screen) -> Overlay {
        let show = match self.pref {
            DisplayPreference::Never => false,
            DisplayPreference::Always => true,
            DisplayPreference::Adaptive => self.srtt_trigger || self.glitch_trigger > 0,
        };
        if !show {
            return Overlay::empty();
        }
        let mut ov = Overlay::empty();
        for (&(row, col), cell) in self.cells.iter() {
            if self.tentative(cell.tentative_epoch) {
                continue; // hidden until its epoch is confirmed
            }
            ov.cells.insert(
                (row, col),
                PredictedCell {
                    glyph: cell.glyph.clone(),
                    fg: cell.fg,
                    bg: cell.bg,
                    underline: self.flagging,
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
    if is_blank(&cell.glyph) {
        return Validity::CorrectNoCredit; // too easy to falsely match
    }
    let actual = cell_glyph(screen, row, col);
    if actual == cell.glyph {
        if actual == cell.original {
            Validity::CorrectNoCredit // it already looked like this; no credit
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
        assert!(ov.cell(0, 1).unwrap().underline, "slow link should flag predictions");
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
        assert!(e.overlay(&blank).is_empty(), "non-echoed input is never shown");

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
}
