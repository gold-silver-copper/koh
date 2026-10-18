//! The terminal the client paints on.
//!
//! [`KohBackend`]'s required methods are the platform primitives (raw mode, the size, writing
//! bytes); its provided methods write every escape sequence. [`Tty`] is the real terminal; tests
//! capture the bytes instead.

use std::fmt;
use std::io;

use fux_vt::{Attributes, SgrForm};

use crate::terminal::{Activity, Link, Size};

mod tty;
pub use self::tty::Tty;

/// The terminal the `koh` binary paints through.
pub type DefaultBackend = Tty;

/// Every input mode koh may have set (mouse reporting and encodings, bracketed paste, focus
/// reporting, cursor and keypad keys), reset on leaving the alternate screen, so the user's shell
/// does not get stray mouse or focus bytes at its prompt.
pub(crate) const RESET_FORWARDED_MODES: &[u8] =
    b"\x1b[?9l\x1b[?2004l\x1b[?1004l\x1b[?1000l\x1b[?1002l\
\x1b[?1003l\x1b[?1005l\x1b[?1006l\x1b[?1l\x1b>";

/// Text for an OSC sequence, without the control characters that would end it early.
///
/// C0 and C1 both go. Only [`OscText::new`] makes one, so a title a server chose reaches the
/// terminal only stripped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OscText(String);

impl OscText {
    pub fn new(text: &str) -> Self {
        Self(text.chars().filter(|c| !c.is_control()).collect())
    }
}

/// A nonce the user's terminal asks marks to carry (`FUX_MARK_NONCE`).
///
/// fux gives it to the programs a shell pane runs: with it, the shell's marks koh writes count in
/// a terminal that ignores marks a program prints without one. A word of at most 64 letters and
/// digits, else none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarkNonce(String);

impl MarkNonce {
    /// The nonce `value` names, if it is one.
    pub fn new(value: &str) -> Option<Self> {
        (!value.is_empty() && value.len() <= 64 && value.bytes().all(|b| b.is_ascii_alphanumeric()))
            .then(|| Self(value.to_owned()))
    }

    /// The nonce in koh's environment, if one is there.
    pub fn from_env() -> Option<Self> {
        Self::new(&std::env::var("FUX_MARK_NONCE").ok()?)
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

    /// The nonce the terminal asks marks to carry, if any.
    fn mark_nonce(&self) -> Option<&MarkNonce> {
        None
    }

    /// Write `OSC 133 ; body`, with the terminal's nonce if it asks for one.
    fn mark(&mut self, body: fmt::Arguments<'_>) -> io::Result<()> {
        match self.mark_nonce().map(|n| n.0.clone()) {
            Some(nonce) => write!(self, "\x1b]133;{body};nonce={nonce}\x07"),
            None => write!(self, "\x1b]133;{body}\x07"),
        }
    }

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

    /// Save the window title (XTWINOPS 22), enter the alternate screen and hide the cursor.
    fn enter_alt_screen(&mut self) -> io::Result<()> {
        self.write_bytes(b"\x1b[22;0t\x1b[?1049h\x1b[?25l")?;
        self.flush()
    }

    /// Reset the forwarded modes, show the cursor, leave the alternate screen and restore the
    /// window title saved on entering it: the user's terminal as it was.
    fn leave_alt_screen(&mut self) -> io::Result<()> {
        self.write_bytes(RESET_FORWARDED_MODES)?;
        self.write_bytes(b"\x1b[?25h\x1b[?1049l\x1b[23;0t")?;
        self.flush()
    }

    /// Open a synchronized-output frame (DEC 2026), hide the cursor and turn autowrap off, so the
    /// frame shows at once and no glyph, the last column's included, can wrap or scroll.
    fn begin_frame(&mut self) -> io::Result<()> {
        self.write_bytes(b"\x1b[?2026h\x1b[?25l\x1b[?7l")
    }

    /// Turn autowrap back on, as the user's shell expects it, and close the frame.
    fn end_frame(&mut self) -> io::Result<()> {
        self.write_bytes(b"\x1b[?7h\x1b[?2026l")
    }

    /// Erase the whole terminal in the default style.
    fn clear(&mut self) -> io::Result<()> {
        self.write_bytes(b"\x1b[m\x1b[2J")
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

    /// Set a whole style, from a reset, in one SGR, as fux-vt paints it: underline styles
    /// (kitty's `4:n`) only where the terminal `styles` them, else a plain underline, as a
    /// terminal that does not know `4:n` draws no underline at all, or reads the colon as a
    /// semicolon (underline and italic).
    fn set_style(&mut self, style: Attributes, styles: bool) -> io::Result<()> {
        let mut sgr = b"\x1b[0".to_vec();
        style.write_sgr(&mut sgr, SgrForm::Paint { styles });
        sgr.push(b'm');
        self.write_bytes(&sgr)
    }

    /// Reset all SGR attributes (`ESC [ m`, the zero-parameter form).
    fn reset_sgr(&mut self) -> io::Result<()> {
        self.write_bytes(b"\x1b[m")
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
    fn set_window_title(&mut self, title: &OscText) -> io::Result<()> {
        write!(self, "\x1b]0;{}\x07", title.0)
    }

    /// Set the icon name (`OSC 1`) and the window title (`OSC 2`).
    fn set_window_icon_and_title(&mut self, icon: &OscText, title: &OscText) -> io::Result<()> {
        write!(self, "\x1b]1;{}\x07\x1b]2;{}\x07", icon.0, title.0)
    }

    /// Set the clipboard (`OSC 52`) to `base64`, which the caller validated.
    fn set_clipboard(&mut self, base64: &str) -> io::Result<()> {
        write!(self, "\x1b]52;c;{base64}\x07")
    }

    /// Open `link` (OSC 8) for the glyphs printed next, with its id if it has one. The caller
    /// checked it is safe to write ([`Link::safe`]).
    fn open_link(&mut self, link: &Link) -> io::Result<()> {
        if link.id.is_empty() {
            write!(self, "\x1b]8;;{}\x1b\\", link.uri)
        } else {
            write!(self, "\x1b]8;id={};{}\x1b\\", link.id, link.uri)
        }
    }

    /// Close the hyperlink open (OSC 8 with no URI).
    fn close_link(&mut self) -> io::Result<()> {
        self.write_bytes(b"\x1b]8;;\x1b\\")
    }

    /// Mark the cursor's row, the cursor in its first column, as where a prompt starts
    /// (`OSC 133 ; A`).
    fn prompt_starts(&mut self) -> io::Result<()> {
        self.mark(format_args!("A"))
    }

    /// Unmark the cursor's row as a prompt's, blanking it: deleted and a blank one inserted in its
    /// place (DL, IL), the rows below put back as they were. A terminal's mark goes only with its
    /// row.
    fn blank_row(&mut self) -> io::Result<()> {
        self.write_bytes(b"\x1b[M\x1b[L")
    }

    /// Say a command's output starts at the cursor (`OSC 133 ; C`).
    fn command_starts(&mut self) -> io::Result<()> {
        self.mark(format_args!("C"))
    }

    /// Say the command ends at the cursor (`OSC 133 ; D`), with its status if known.
    fn command_ends(&mut self, status: Option<i32>) -> io::Result<()> {
        match status {
            Some(status) => self.mark(format_args!("D;{status}")),
            None => self.mark(format_args!("D")),
        }
    }

    /// Report what the remote program is doing (`OSC 133 ; S ; activity=STATE`), as fux reads it.
    fn activity(&mut self, activity: Activity) -> io::Result<()> {
        self.mark(format_args!("S;activity={}", activity.name()))
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
    use fux_vt::{Blink, Color, UnderlineStyle};

    /// A capture whose terminal asks marks to carry a nonce.
    struct Nonced(CaptureBackend, Option<MarkNonce>);

    impl KohBackend for Nonced {
        fn write_bytes(&mut self, bytes: &[u8]) -> io::Result<()> {
            self.0.write_bytes(bytes)
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
            Ok(self.0.size)
        }
        fn mark_nonce(&self) -> Option<&MarkNonce> {
            self.1.as_ref()
        }
    }

    #[test]
    fn marks_carry_the_nonce_the_terminal_asks_for_and_only_a_word_is_one() {
        let marks = |nonce| {
            let mut b = Nonced(CaptureBackend::default(), nonce);
            b.prompt_starts().unwrap();
            b.command_starts().unwrap();
            b.command_ends(Some(1)).unwrap();
            b.command_ends(None).unwrap();
            b.activity(Activity::Reading).unwrap();
            String::from_utf8(b.0.bytes).unwrap()
        };
        assert_eq!(
            marks(None),
            "\x1b]133;A\x07\x1b]133;C\x07\x1b]133;D;1\x07\x1b]133;D\x07\x1b]133;S;activity=reading\x07"
        );
        assert_eq!(
            marks(MarkNonce::new("ab12")),
            "\x1b]133;A;nonce=ab12\x07\x1b]133;C;nonce=ab12\x07\x1b]133;D;1;nonce=ab12\x07\x1b]133;D;nonce=ab12\x07\
             \x1b]133;S;activity=reading;nonce=ab12\x07"
        );
        for bad in ["", "a;b", "a\x07", &"x".repeat(65)] {
            assert_eq!(MarkNonce::new(bad), None, "{bad:?}");
        }
    }

    /// Capture the bytes a single provided method emits.
    fn emit(f: impl FnOnce(&mut CaptureBackend) -> io::Result<()>) -> Vec<u8> {
        let mut b = CaptureBackend::default();
        f(&mut b).expect("capture backend never errors");
        b.bytes
    }

    /// The 16 palette colours use the theme-aware 30–37 / 90–97 (40–47 / 100–107) codes, not the
    /// fixed 256-palette `38;5;n` form, so a user's terminal theme still recolors them.
    #[test]
    fn sgr_colors_are_the_classic_theme_aware_codes_where_they_can_be() {
        let blue = Color::Rgb(fux_vt::Rgb { r: 0, g: 0, b: 255 });
        for (fg, bg, sgr) in [
            (Color::Idx(1), Color::Idx(9), &b"\x1b[0;31;101m"[..]),
            (Color::Idx(15), Color::Idx(4), b"\x1b[0;97;44m"),
            (Color::Idx(196), blue, b"\x1b[0;38;5;196;48;2;0;0;255m"),
        ] {
            let style = Attributes::new(fg, bg);
            assert_eq!(emit(|b| b.set_style(style, true)), sgr, "{style:?}");
        }
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
        assert_eq!(
            emit(KohBackend::begin_frame),
            b"\x1b[?2026h\x1b[?25l\x1b[?7l"
        );
        assert_eq!(emit(KohBackend::end_frame), b"\x1b[?7h\x1b[?2026l");
        // The user's title is saved on entering, and restored on leaving (exit and suspend).
        assert_eq!(
            emit(KohBackend::enter_alt_screen),
            b"\x1b[22;0t\x1b[?1049h\x1b[?25l"
        );
        // leave_alt_screen resets the forwarded-mode ledger, then shows the cursor and leaves alt.
        let bytes = emit(KohBackend::leave_alt_screen);
        assert!(bytes.starts_with(RESET_FORWARDED_MODES));
        assert!(bytes.ends_with(b"\x1b[?25h\x1b[?1049l\x1b[23;0t"));
    }

    #[test]
    fn a_style_emits_every_attribute_it_has() {
        let plain = Attributes::new(Color::Idx(1), Color::Default);
        let style = plain
            .with_underline_color(Color::Rgb(fux_vt::Rgb { r: 1, g: 2, b: 3 }))
            .with_underline_style(UnderlineStyle::Single)
            .with_hidden(true)
            .with_strikeout(true)
            .with_blink(Blink::Rapid);
        assert_eq!(
            emit(|b| b.set_style(style, true)),
            b"\x1b[0;8;9;4;6;58:2::1:2:3;31m"
        );
        assert_eq!(emit(|b| b.set_style(plain, true)), b"\x1b[0;31m");
        // Each underline style, where the terminal draws them; plain where it does not.
        for (underline, sgr) in [
            (UnderlineStyle::Double, &b"\x1b[0;4:2;31m"[..]),
            (UnderlineStyle::Curly, b"\x1b[0;4:3;31m"),
            (UnderlineStyle::Dotted, b"\x1b[0;4:4;31m"),
            (UnderlineStyle::Dashed, b"\x1b[0;4:5;31m"),
        ] {
            let styled = plain.with_underline_style(underline);
            assert_eq!(emit(|b| b.set_style(styled, true)), sgr);
            assert_eq!(emit(|b| b.set_style(styled, false)), b"\x1b[0;4;31m");
        }
    }

    #[test]
    fn scroll_region_bytes() {
        assert_eq!(emit(|b| b.scroll_region(0, 24, -1)), b"\x1b[1;24r\x1b[1S");
        assert_eq!(emit(|b| b.scroll_region(4, 20, 3)), b"\x1b[5;20r\x1b[3T");
        assert_eq!(emit(KohBackend::reset_scroll_region), b"\x1b[r");
    }

    #[test]
    fn out_of_band_escapes() {
        assert_eq!(
            emit(|b| b.set_window_title(&OscText::new("x\x07\u{9c}"))),
            b"\x1b]0;x\x07"
        );
        assert_eq!(
            emit(|b| b.set_window_icon_and_title(&OscText::new("i"), &OscText::new("t"))),
            b"\x1b]1;i\x07\x1b]2;t\x07"
        );
        assert_eq!(emit(|b| b.set_clipboard("aGk=")), b"\x1b]52;c;aGk=\x07");
        assert_eq!(emit(KohBackend::bell), b"\x07");
    }
}
