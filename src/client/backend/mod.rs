//! The terminal the client paints on.
//!
//! [`KohBackend`]'s required methods are the platform primitives (raw mode, the size, writing
//! bytes); its provided methods write every escape sequence. [`Tty`] is the real terminal; tests
//! capture the bytes instead.

use std::fmt;
use std::io;

use fux_vt::{Blink, Color, UnderlineStyle};

use crate::terminal::Size;

mod tty;
pub use self::tty::Tty;

/// The terminal the `koh` binary paints through.
pub type DefaultBackend = Tty;

/// Every mode koh may have forwarded (mouse reporting and encodings, bracketed paste, cursor and
/// keypad keys), reset on leaving the alternate screen, so the user's shell does not get stray
/// mouse bytes at its prompt.
pub(crate) const RESET_FORWARDED_MODES: &[u8] =
    b"\x1b[?9l\x1b[?2004l\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1005l\x1b[?1006l\x1b[?1l\x1b>";

/// A cell's style as koh draws it, compared with the last to emit SGR only on a change.
#[derive(PartialEq, Eq, Clone, Copy)]
pub struct CellStyle {
    pub fg: Color,
    pub bg: Color,
    pub underline_color: Color,
    pub bold: bool,
    pub dim: bool,
    pub italic: bool,
    pub underline: UnderlineStyle,
    pub inverse: bool,
    pub hidden: bool,
    pub strikeout: bool,
    pub blink: Blink,
}

impl CellStyle {
    /// This style as a terminal draws it: an underline's style only if `styles` (the terminal
    /// draws them), else a plain underline. A terminal that does not know `4:n` draws no underline
    /// at all, or reads the colon as a semicolon (underline and italic).
    #[must_use]
    pub fn drawn(self, styles: bool) -> Self {
        let underline = match self.underline {
            UnderlineStyle::None => UnderlineStyle::None,
            style @ (UnderlineStyle::Double
            | UnderlineStyle::Curly
            | UnderlineStyle::Dotted
            | UnderlineStyle::Dashed)
                if styles =>
            {
                style
            }
            UnderlineStyle::Single | _ => UnderlineStyle::Single,
        };
        Self { underline, ..self }
    }
}

/// The terminal `koh connect` paints on. Output is buffered until [`flush`](Self::flush), once per
/// frame.
pub trait KohBackend {
    /// Append bytes to the output buffer.
    fn write_bytes(&mut self, bytes: &[u8]) -> io::Result<()>;

    /// Write the buffered output to the terminal.
    fn flush(&mut self) -> io::Result<()>;

    /// Put the terminal in raw mode.
    fn enter_raw_mode(&mut self) -> io::Result<()>;

    /// Restore the terminal's mode; harmless if raw mode was never entered.
    fn leave_raw_mode(&mut self) -> io::Result<()>;

    /// The current terminal size.
    fn size(&self) -> io::Result<Size>;

    /// Format `args` into the output buffer with no intermediate `String`; what `write!` calls.
    fn write_fmt(&mut self, args: fmt::Arguments<'_>) -> io::Result<()> {
        /// Forwards formatted pieces to the backend, keeping the first I/O error for the caller.
        struct Pieces<'a, B: ?Sized> {
            backend: &'a mut B,
            error: io::Result<()>,
        }
        impl<B: KohBackend + ?Sized> fmt::Write for Pieces<'_, B> {
            fn write_str(&mut self, s: &str) -> fmt::Result {
                self.backend.write_bytes(s.as_bytes()).map_err(|e| {
                    self.error = Err(e);
                    fmt::Error
                })
            }
        }
        let mut pieces = Pieces {
            backend: self,
            error: Ok(()),
        };
        if fmt::write(&mut pieces, args).is_err() {
            // A formatter fails only through `write_str`, which kept the I/O error.
            pieces.error?;
            return Err(io::Error::other("formatting failed"));
        }
        Ok(())
    }

    /// Enter the alternate screen and hide the cursor.
    fn enter_alt_screen(&mut self) -> io::Result<()> {
        self.write_bytes(b"\x1b[?1049h\x1b[?25l")?;
        self.flush()
    }

    /// Reset the forwarded modes, show the cursor and leave the alternate screen: the user's
    /// terminal as it was.
    fn leave_alt_screen(&mut self) -> io::Result<()> {
        self.write_bytes(RESET_FORWARDED_MODES)?;
        self.write_bytes(b"\x1b[?25h\x1b[?1049l")?;
        self.flush()
    }

    /// Open a synchronized-output frame (DEC 2026) and hide the cursor, so the frame shows at once.
    fn begin_frame(&mut self) -> io::Result<()> {
        self.write_bytes(b"\x1b[?2026h\x1b[?25l")
    }

    /// Close the synchronized-output frame.
    fn end_frame(&mut self) -> io::Result<()> {
        self.write_bytes(b"\x1b[?2026l")
    }

    /// Move the cursor to a 0-based `(row, col)` (emitted as the 1-based CUP sequence).
    fn move_to(&mut self, row: u16, col: u16) -> io::Result<()> {
        // In u32, so `u16::MAX + 1` cannot overflow.
        write!(self, "\x1b[{};{}H", u32::from(row) + 1, u32::from(col) + 1)
    }

    /// Scroll the 0-based rows `top..bottom` by `by` (negative is up) inside a scroll region
    /// (DECSTBM, then SU or SD), leaving the region set and the cursor home. `top..bottom` holds at
    /// least two rows.
    fn scroll_region(&mut self, top: u16, bottom: u16, by: i16) -> io::Result<()> {
        write!(self, "\x1b[{};{}r", u32::from(top) + 1, bottom)?;
        let lines = by.unsigned_abs();
        if by < 0 {
            write!(self, "\x1b[{lines}S")
        } else {
            write!(self, "\x1b[{lines}T")
        }
    }

    /// Reset the scroll region to the whole terminal (DECSTBM without parameters), moving the
    /// cursor home.
    fn reset_scroll_region(&mut self) -> io::Result<()> {
        self.write_bytes(b"\x1b[r")
    }

    /// Set a whole style: reset, then each attribute, then the colours.
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
        match style.underline {
            UnderlineStyle::None => {}
            // Kitty's `4:n`, only where the terminal draws it (see `CellStyle::drawn`).
            UnderlineStyle::Double => self.write_bytes(b"\x1b[4:2m")?,
            UnderlineStyle::Curly => self.write_bytes(b"\x1b[4:3m")?,
            UnderlineStyle::Dotted => self.write_bytes(b"\x1b[4:4m")?,
            UnderlineStyle::Dashed => self.write_bytes(b"\x1b[4:5m")?,
            // A style fux-vt adds later is drawn plain.
            UnderlineStyle::Single | _ => self.write_bytes(b"\x1b[4m")?,
        }
        if style.inverse {
            self.write_bytes(b"\x1b[7m")?;
        }
        if style.hidden {
            self.write_bytes(b"\x1b[8m")?;
        }
        if style.strikeout {
            self.write_bytes(b"\x1b[9m")?;
        }
        match style.blink {
            Blink::Slow => self.write_bytes(b"\x1b[5m")?,
            Blink::Rapid => self.write_bytes(b"\x1b[6m")?,
            Blink::None | _ => {}
        }
        write_sgr_color(self, style.fg, true)?;
        write_sgr_color(self, style.bg, false)?;
        // Only when set: a terminal that does not know SGR 58 may read its parameters as others.
        write_underline_color(self, style.underline_color)
    }

    /// Reset all SGR attributes (`ESC [ m`, the zero-parameter form).
    fn reset_sgr(&mut self) -> io::Result<()> {
        self.write_bytes(b"\x1b[m")
    }

    /// Turn on reverse video (`ESC [ 7 m`), for the status line.
    fn set_reverse(&mut self) -> io::Result<()> {
        self.write_bytes(b"\x1b[7m")
    }

    /// Print a glyph at the cursor.
    fn print(&mut self, glyph: &str) -> io::Result<()> {
        self.write_bytes(glyph.as_bytes())
    }

    /// Show the cursor (`ESC [ ? 25 h`).
    fn show_cursor(&mut self) -> io::Result<()> {
        self.write_bytes(b"\x1b[?25h")
    }

    /// Set the window title and icon name together (`OSC 0`).
    fn set_window_title(&mut self, title: &str) -> io::Result<()> {
        write!(self, "\x1b]0;{title}\x07")
    }

    /// Set the icon name (`OSC 1`) and the window title (`OSC 2`).
    fn set_window_icon_and_title(&mut self, icon: &str, title: &str) -> io::Result<()> {
        write!(self, "\x1b]1;{icon}\x07\x1b]2;{title}\x07")
    }

    /// Set the clipboard (`OSC 52`) to `base64`, which the caller validated.
    fn set_clipboard(&mut self, base64: &str) -> io::Result<()> {
        write!(self, "\x1b]52;c;{base64}\x07")
    }

    /// Ring the terminal bell (BEL).
    fn bell(&mut self) -> io::Result<()> {
        self.write_bytes(b"\x07")
    }

    /// Write the sequences that set the program's input modes.
    fn write_input_modes(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.write_bytes(bytes)
    }
}

/// Emit `color` as the underline colour (SGR 58), unless it is the default (the text's colour),
/// which the reset before every style already restored.
fn write_underline_color(out: &mut (impl KohBackend + ?Sized), color: Color) -> io::Result<()> {
    match color {
        Color::Idx(i) => write!(out, "\x1b[58;5;{i}m"),
        Color::Rgb(r, g, b) => write!(out, "\x1b[58;2;{r};{g};{b}m"),
        Color::Default | _ => Ok(()),
    }
}

/// Emit `color` as the foreground (`fg`) or background. Indices 0–15 use the classic 30–37/90–97
/// (40–47/100–107) codes, which follow the user's theme, rather than `38;5;n`.
fn write_sgr_color(out: &mut (impl KohBackend + ?Sized), color: Color, fg: bool) -> io::Result<()> {
    match color {
        Color::Idx(i) if i < 8 => {
            let lead = if fg { 3 } else { 4 };
            write!(out, "\x1b[{lead}{i}m")
        }
        Color::Idx(i) if i < 16 => {
            let lead = if fg { 9 } else { 10 };
            write!(out, "\x1b[{lead}{}m", i & 7)
        }
        Color::Idx(i) => {
            let lead = if fg { 38 } else { 48 };
            write!(out, "\x1b[{lead};5;{i}m")
        }
        Color::Rgb(r, g, b) => {
            let lead = if fg { 38 } else { 48 };
            write!(out, "\x1b[{lead};2;{r};{g};{b}m")
        }
        Color::Default | _ => out.write_bytes(if fg { b"\x1b[39m" } else { b"\x1b[49m" }),
    }
}

/// A backend that captures the bytes a terminal would receive, for tests. It reports `size`, 24×80
/// by default.
#[cfg(test)]
pub(crate) struct CaptureBackend {
    pub bytes: Vec<u8>,
    pub size: Size,
}

#[cfg(test)]
impl Default for CaptureBackend {
    fn default() -> Self {
        Self {
            bytes: Vec::new(),
            size: Size::new(24, 80),
        }
    }
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
    fn size(&self) -> io::Result<Size> {
        Ok(self.size)
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
    fn sgr_codes_for_the_16_palette_colors_are_exactly_30_37_90_97_and_40_47_100_107() {
        for i in 0..16u8 {
            for (fg, low, high) in [(true, 30, 90), (false, 40, 100)] {
                let code = if i < 8 { low + i } else { high + i - 8 };
                assert_eq!(
                    emit(|b| write_sgr_color(b, Color::Idx(i), fg)),
                    format!("\x1b[{code}m").into_bytes(),
                    "index {i}, fg {fg}"
                );
            }
        }
    }

    #[test]
    fn sgr_colors_match_the_classic_theme_aware_codes() {
        // Low palette indices use the theme-aware 30–37 / 90–97 codes (not the fixed 256-palette
        // 38;5;n form), so a user's terminal theme still recolors them.
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
    fn a_style_emits_every_attribute_it_has() {
        let style = CellStyle {
            fg: Color::Idx(1),
            bg: Color::Default,
            underline_color: Color::Rgb(1, 2, 3),
            bold: false,
            dim: false,
            italic: false,
            underline: UnderlineStyle::Single,
            inverse: false,
            hidden: true,
            strikeout: true,
            blink: Blink::Rapid,
        };
        assert_eq!(
            emit(|b| b.set_style(style)),
            b"\x1b[m\x1b[4m\x1b[8m\x1b[9m\x1b[6m\x1b[31m\x1b[49m\x1b[58;2;1;2;3m"
        );
        let plain = CellStyle {
            underline_color: Color::Default,
            hidden: false,
            strikeout: false,
            blink: Blink::None,
            underline: UnderlineStyle::None,
            ..style
        };
        assert_eq!(emit(|b| b.set_style(plain)), b"\x1b[m\x1b[31m\x1b[49m");
        // Each underline style, where the terminal draws them; plain where it does not.
        for (underline, sgr) in [
            (UnderlineStyle::Double, &b"\x1b[4:2m"[..]),
            (UnderlineStyle::Curly, b"\x1b[4:3m"),
            (UnderlineStyle::Dotted, b"\x1b[4:4m"),
            (UnderlineStyle::Dashed, b"\x1b[4:5m"),
        ] {
            let styled = CellStyle { underline, ..plain };
            assert_eq!(
                emit(|b| b.set_style(styled.drawn(true))),
                [b"\x1b[m", sgr, b"\x1b[31m\x1b[49m"].concat()
            );
            assert_eq!(
                emit(|b| b.set_style(styled.drawn(false))),
                b"\x1b[m\x1b[4m\x1b[31m\x1b[49m"
            );
        }
        assert_eq!(
            emit(|b| write_underline_color(b, Color::Idx(200))),
            b"\x1b[58;5;200m"
        );
    }

    #[test]
    fn scroll_region_bytes() {
        assert_eq!(emit(|b| b.scroll_region(0, 24, -1)), b"\x1b[1;24r\x1b[1S");
        assert_eq!(emit(|b| b.scroll_region(4, 20, 3)), b"\x1b[5;20r\x1b[3T");
        assert_eq!(emit(KohBackend::reset_scroll_region), b"\x1b[r");
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
