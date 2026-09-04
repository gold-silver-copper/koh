//! The pluggable terminal backend seam: [`KohBackend`] and its concrete implementations.
//!
//! The client's render path (`super::render`) and its [`ClientTerminal`](super::ClientTerminal)
//! adapter ([`BackendTerminal`](super::BackendTerminal)) speak **only** to [`KohBackend`] — never to
//! `termina`, `crossterm`, or any other terminal crate directly. A backend supplies the handful of
//! genuinely platform-specific operations (enter/leave raw mode, query the size, write bytes) and
//! inherits every escape-sequence emission (the cell grid, the cursor, the out-of-band window state)
//! as **provided methods** that write standard ANSI/DEC sequences. So adding a backend is small — a
//! few lines wiring up its raw-mode + size ioctls — and the escape output is identical across all of
//! them, byte-for-byte with the pre-abstraction `termina` path.
//!
//! The provided methods are what a backend *may* override: a backend that wants to own its escape
//! encoding (e.g. to route through its own ordered-output/policy layer) can replace any of them, but
//! none of the current backends need to — the ANSI koh emits is understood by every real terminal
//! regardless of which crate put it into raw mode.
//!
//! ## Backend selection
//!
//! Exactly one backend is compiled into the `koh` binary, chosen by cargo feature: `backend-termina`
//! (default), `backend-crossterm`, or `backend-qwertty`. [`DefaultBackend`] resolves to the enabled
//! one; enabling several keeps the highest-precedence (`termina` first, a plain build is unchanged),
//! and enabling none is a compile error rather than a client that cannot paint.

use std::io;

use vt100::Color;

#[cfg(feature = "backend-termina")]
mod termina;
#[cfg(feature = "backend-termina")]
pub use self::termina::TerminaBackend;

#[cfg(feature = "backend-crossterm")]
mod crossterm;
#[cfg(feature = "backend-crossterm")]
pub use self::crossterm::CrosstermBackend;

#[cfg(feature = "backend-qwertty")]
mod qwertty;
#[cfg(feature = "backend-qwertty")]
pub use self::qwertty::QwerttyBackend;

/// The backend the `koh` binary paints through, resolved at build time.
///
/// Precedence when several backend features are on: `backend-termina` (the default) beats
/// `backend-crossterm` beats `backend-qwertty`, so enabling an alternate alongside the default does
/// not change a default build. A build with *no* backend feature trips the `compile_error!` below
/// instead of silently producing a client with no renderer.
#[cfg(feature = "backend-termina")]
pub type DefaultBackend = TerminaBackend;
#[cfg(all(feature = "backend-crossterm", not(feature = "backend-termina")))]
pub type DefaultBackend = CrosstermBackend;
#[cfg(all(
    feature = "backend-qwertty",
    not(feature = "backend-termina"),
    not(feature = "backend-crossterm")
))]
pub type DefaultBackend = QwerttyBackend;

#[cfg(not(any(
    feature = "backend-termina",
    feature = "backend-crossterm",
    feature = "backend-qwertty"
)))]
compile_error!(
    "koh's client needs a terminal backend: enable `backend-termina` (default), `backend-crossterm`, or `backend-qwertty`"
);

/// The DEC private modes koh may have forwarded to the user's terminal (X10 `?9` + all mouse modes
/// and encodings, bracketed paste `?2004`, application cursor keys `?1`) plus normal keypad
/// (`ESC >`). Reset together whenever koh leaves the alternate screen — on drop *or* on suspend — so
/// the user's shell isn't left with mouse reporting on, injecting stray bytes at the prompt.
///
/// This ledger is deliberately **backend-independent**: it lives here (not in any one backend) and
/// is emitted by [`KohBackend::leave_alt_screen`], so every backend restores the same mode set.
pub(crate) const RESET_FORWARDED_MODES: &[u8] =
    b"\x1b[?9l\x1b[?2004l\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1005l\x1b[?1006l\x1b[?1l\x1b>";

/// A compact, backend-neutral style fingerprint for one cell.
///
/// Carries only what koh renders (fg/bg plus the boolean attributes vt100 exposes); `Copy` +
/// `PartialEq` so the render loop can diff it against the previous cell and re-emit SGR only when it
/// actually changes.
#[derive(PartialEq, Eq, Clone, Copy)]
pub struct CellStyle {
    pub fg: Color,
    pub bg: Color,
    pub bold: bool,
    pub dim: bool,
    pub italic: bool,
    pub underline: bool,
    pub inverse: bool,
}

/// A pluggable terminal backend for the `koh connect` client.
///
/// Modeled on Ratatui's `Backend`, but split so the escape-sequence emission (the provided methods)
/// is shared and only the platform primitives (the required methods) vary per backend. Callers hold
/// a backend inside [`BackendTerminal`](super::BackendTerminal), which owns the mode ledger and the
/// frame lifecycle; a backend itself is stateless beyond its terminal handle.
///
/// All output is buffered by the backend and made visible by [`flush`](Self::flush) — the render
/// path flushes once per frame, so a repaint reaches the terminal atomically (it is additionally
/// wrapped in DEC synchronized output by [`begin_frame`](Self::begin_frame) /
/// [`end_frame`](Self::end_frame)).
pub trait KohBackend {
    // --- required: the genuinely platform-specific operations ---

    /// Append raw bytes to the output buffer (not necessarily flushed until [`flush`](Self::flush)).
    fn write_bytes(&mut self, bytes: &[u8]) -> io::Result<()>;

    /// Flush buffered output so it becomes visible on the terminal.
    fn flush(&mut self) -> io::Result<()>;

    /// Put the terminal into raw mode (no line buffering, no echo, no signal-generating keys).
    fn enter_raw_mode(&mut self) -> io::Result<()>;

    /// Return the terminal to cooked mode. Must be safe to call even if raw mode was never entered.
    fn leave_raw_mode(&mut self) -> io::Result<()>;

    /// The current terminal size as `(rows, cols)`.
    fn size(&self) -> io::Result<(u16, u16)>;

    // --- provided: standard ANSI/DEC emission (override only to use a different encoding) ---

    /// Enter the alternate screen (clearing it) and hide the cursor, then flush. Paired with
    /// [`leave_alt_screen`](Self::leave_alt_screen). DEC 1049 + hide-cursor.
    fn enter_alt_screen(&mut self) -> io::Result<()> {
        self.write_bytes(b"\x1b[?1049h\x1b[?25l")?;
        self.flush()
    }

    /// Reset the forwarded input modes (`RESET_FORWARDED_MODES`), show the cursor, and leave the
    /// alternate screen, then flush. This is the teardown that restores the user's terminal on drop
    /// and on suspend — kept here (not in the caller) so it runs identically for every backend.
    fn leave_alt_screen(&mut self) -> io::Result<()> {
        self.write_bytes(RESET_FORWARDED_MODES)?;
        self.write_bytes(b"\x1b[?25h\x1b[?1049l")?;
        self.flush()
    }

    /// Begin one repaint: open a DEC synchronized-output frame (mode 2026) and hide the cursor while
    /// painting, so the terminal reveals the whole frame at once with no tearing.
    fn begin_frame(&mut self) -> io::Result<()> {
        self.write_bytes(b"\x1b[?2026h\x1b[?25l")
    }

    /// End the repaint: close the synchronized-output frame. The terminal now shows the frame.
    fn end_frame(&mut self) -> io::Result<()> {
        self.write_bytes(b"\x1b[?2026l")
    }

    /// Move the cursor to a 0-based `(row, col)` (emitted as the 1-based CUP sequence).
    fn move_to(&mut self, row: u16, col: u16) -> io::Result<()> {
        // u32 math so the `+ 1` can never overflow the u16 coordinate (overflow-checks are on in
        // release), and cols/rows are peer-controlled (though clamped) — never trust them not to be
        // at the type max.
        self.write_bytes(format!("\x1b[{};{}H", u32::from(row) + 1, u32::from(col) + 1).as_bytes())
    }

    /// Apply a full cell style: SGR reset, then each set attribute, then fg and bg. Emitted only
    /// when the style changes (the render loop diffs), so this is not on the per-cell hot path.
    fn set_style(&mut self, style: CellStyle) -> io::Result<()> {
        self.reset_sgr()?; // clears everything (incl. colors), then re-apply
        if style.bold {
            self.write_bytes(b"\x1b[1m")?;
        }
        if style.dim {
            self.write_bytes(b"\x1b[2m")?;
        }
        if style.italic {
            self.write_bytes(b"\x1b[3m")?;
        }
        if style.underline {
            self.write_bytes(b"\x1b[4m")?;
        }
        if style.inverse {
            self.write_bytes(b"\x1b[7m")?;
        }
        write_sgr_color(self, style.fg, true)?;
        write_sgr_color(self, style.bg, false)
    }

    /// Reset all SGR attributes (`ESC [ m`, the zero-parameter form).
    fn reset_sgr(&mut self) -> io::Result<()> {
        self.write_bytes(b"\x1b[m")
    }

    /// Turn on reverse video (`ESC [ 7 m`) — used for the status line.
    fn set_reverse(&mut self) -> io::Result<()> {
        self.write_bytes(b"\x1b[7m")
    }

    /// Print a glyph at the current cursor position. `glyph` is borrowed (from the screen grid or
    /// the prediction overlay), so the per-cell hot path never allocates.
    fn print(&mut self, glyph: &str) -> io::Result<()> {
        self.write_bytes(glyph.as_bytes())
    }

    /// Show the cursor (`ESC [ ? 25 h`). The render path calls this after positioning the cursor,
    /// only when the remote screen wants it visible.
    fn show_cursor(&mut self) -> io::Result<()> {
        self.write_bytes(b"\x1b[?25h")
    }

    /// Set the combined window title + icon name (`OSC 0`), used when the app's icon name equals its
    /// title. `title` is already sanitized/prefixed by the caller's ledger.
    fn set_window_title(&mut self, title: &str) -> io::Result<()> {
        self.write_bytes(format!("\x1b]0;{title}\x07").as_bytes())
    }

    /// Set a distinct icon name (`OSC 1`) and window title (`OSC 2`). Both are sanitized/prefixed by
    /// the caller's ledger.
    fn set_window_icon_and_title(&mut self, icon: &str, title: &str) -> io::Result<()> {
        self.write_bytes(format!("\x1b]1;{icon}\x07\x1b]2;{title}\x07").as_bytes())
    }

    /// Forward an OSC-52 clipboard write (`OSC 52`). The caller has already gated this on the
    /// `--clipboard` opt-in and validated `base64` as strict base64 within the size cap.
    fn set_clipboard(&mut self, base64: &str) -> io::Result<()> {
        self.write_bytes(format!("\x1b]52;c;{base64}\x07").as_bytes())
    }

    /// Ring the terminal bell (BEL).
    fn bell(&mut self) -> io::Result<()> {
        self.write_bytes(b"\x07")
    }

    /// Re-assert the remote app's input modes (bracketed paste / mouse reporting / application
    /// cursor keys) on the local terminal. `bytes` are the DEC-private-mode set/reset escapes vt100
    /// produced by diffing the screen's mode state, forwarded verbatim so the local terminal reports
    /// input exactly as the remote app expects.
    fn write_input_modes(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.write_bytes(bytes)
    }
}

/// Emit one SGR color parameter for `color` on the foreground (`fg == true`) or background layer.
///
/// Mirrors `termina`'s encoding exactly so the abstraction is byte-for-byte compatible with the
/// pre-refactor output: palette indices 0–7 map to the classic 30–37 / 40–47 codes and 8–15 to the
/// bright 90–97 / 100–107 codes (both **theme-aware** — the terminal's palette, not the fixed
/// 256-color slots), 16–255 to `38;5;n` / `48;5;n`, true color to `38;2;r;g;b` / `48;2;r;g;b`, and
/// the default color to `39` / `49`.
fn write_sgr_color(out: &mut (impl KohBackend + ?Sized), color: Color, fg: bool) -> io::Result<()> {
    match color {
        Color::Default => out.write_bytes(if fg { b"\x1b[39m" } else { b"\x1b[49m" }),
        Color::Idx(i) if i < 8 => {
            let base: u16 = if fg { 30 } else { 40 };
            out.write_bytes(format!("\x1b[{}m", base + u16::from(i)).as_bytes())
        }
        Color::Idx(i) if i < 16 => {
            // 8..=15 → 90..=97 (fg) / 100..=107 (bg): base is 8 below the first bright code.
            let base: u16 = if fg { 82 } else { 92 };
            out.write_bytes(format!("\x1b[{}m", base + u16::from(i)).as_bytes())
        }
        Color::Idx(i) => {
            let lead = if fg { 38 } else { 48 };
            out.write_bytes(format!("\x1b[{lead};5;{i}m").as_bytes())
        }
        Color::Rgb(r, g, b) => {
            let lead = if fg { 38 } else { 48 };
            out.write_bytes(format!("\x1b[{lead};2;{r};{g};{b}m").as_bytes())
        }
    }
}

/// An in-memory backend that captures every emitted byte, for unit-testing the render engine and
/// out-of-band emission without a real TTY. All the platform primitives are inert; the escape
/// output comes from the trait's provided methods, so tests observe exactly what a real terminal
/// would receive.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct CaptureBackend {
    pub bytes: Vec<u8>,
}

#[cfg(test)]
impl KohBackend for CaptureBackend {
    fn write_bytes(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn enter_raw_mode(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn leave_raw_mode(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn size(&self) -> io::Result<(u16, u16)> {
        Ok((24, 80))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Capture the bytes a single provided method emits.
    fn emit(f: impl FnOnce(&mut CaptureBackend) -> io::Result<()>) -> Vec<u8> {
        let mut b = CaptureBackend::default();
        f(&mut b).expect("capture backend never errors");
        b.bytes
    }

    #[test]
    fn sgr_colors_match_the_classic_theme_aware_codes() {
        // Low palette indices use the theme-aware 30–37 / 90–97 codes (not the fixed 256-palette
        // 38;5;n form), so a user's terminal theme still recolors them — this is the property the
        // pre-abstraction termina path had, preserved exactly.
        assert_eq!(
            emit(|b| write_sgr_color(b, Color::Idx(1), true)),
            b"\x1b[31m"
        );
        assert_eq!(
            emit(|b| write_sgr_color(b, Color::Idx(7), true)),
            b"\x1b[37m"
        );
        assert_eq!(
            emit(|b| write_sgr_color(b, Color::Idx(8), true)),
            b"\x1b[90m"
        );
        assert_eq!(
            emit(|b| write_sgr_color(b, Color::Idx(15), true)),
            b"\x1b[97m"
        );
        assert_eq!(
            emit(|b| write_sgr_color(b, Color::Idx(196), true)),
            b"\x1b[38;5;196m"
        );
        assert_eq!(
            emit(|b| write_sgr_color(b, Color::Rgb(0, 0, 255), true)),
            b"\x1b[38;2;0;0;255m"
        );
        assert_eq!(
            emit(|b| write_sgr_color(b, Color::Default, true)),
            b"\x1b[39m"
        );
        // Background layer: 40–47 / 100–107 / 48;5;n / 48;2 / 49.
        assert_eq!(
            emit(|b| write_sgr_color(b, Color::Idx(1), false)),
            b"\x1b[41m"
        );
        assert_eq!(
            emit(|b| write_sgr_color(b, Color::Idx(8), false)),
            b"\x1b[100m"
        );
        assert_eq!(
            emit(|b| write_sgr_color(b, Color::Idx(196), false)),
            b"\x1b[48;5;196m"
        );
        assert_eq!(
            emit(|b| write_sgr_color(b, Color::Default, false)),
            b"\x1b[49m"
        );
    }

    #[test]
    fn move_to_is_one_based_and_overflow_safe() {
        assert_eq!(emit(|b| b.move_to(0, 0)), b"\x1b[1;1H");
        assert_eq!(emit(|b| b.move_to(23, 79)), b"\x1b[24;80H");
        // A u16::MAX coordinate must format (as 65536) rather than panic on the `+ 1`.
        assert_eq!(emit(|b| b.move_to(u16::MAX, 0)), b"\x1b[65536;1H");
    }

    #[test]
    fn frame_and_screen_control_bytes() {
        assert_eq!(emit(KohBackend::begin_frame), b"\x1b[?2026h\x1b[?25l");
        assert_eq!(emit(KohBackend::end_frame), b"\x1b[?2026l");
        assert_eq!(emit(KohBackend::enter_alt_screen), b"\x1b[?1049h\x1b[?25l");
        // leave_alt_screen resets the forwarded-mode ledger, then shows the cursor and leaves alt.
        let bytes = emit(KohBackend::leave_alt_screen);
        assert!(bytes.starts_with(RESET_FORWARDED_MODES));
        assert!(bytes.ends_with(b"\x1b[?25h\x1b[?1049l"));
    }

    #[test]
    fn out_of_band_escapes() {
        assert_eq!(emit(|b| b.set_window_title("x")), b"\x1b]0;x\x07");
        assert_eq!(
            emit(|b| b.set_window_icon_and_title("i", "t")),
            b"\x1b]1;i\x07\x1b]2;t\x07"
        );
        assert_eq!(emit(|b| b.set_clipboard("aGk=")), b"\x1b]52;c;aGk=\x07");
        assert_eq!(emit(KohBackend::bell), b"\x07");
    }
}
