//! The terminal `koh connect` writes to.
//!
//! [`KohBackend`]'s required methods are the platform primitives (raw mode, the size, writing
//! bytes); [`Tty`] is the real terminal; tests capture the bytes instead.

use std::fmt;
use std::io;

use crate::terminal::Size;

mod tty;
pub use self::tty::Tty;

/// The terminal the `koh` binary writes to.
pub type DefaultBackend = Tty;

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

/// The terminal `koh connect` writes to. Output is buffered until [`flush`](Self::flush).
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

    /// The overlay now painted over the program's output: the predicted glyphs and the status
    /// line, for a test terminal to tell from what the program wrote. Default: nothing.
    fn overlay(&mut self, _predicted: &str, _status: Option<&str>) {}

    /// Write `OSC 133 ; body`, with the terminal's nonce if it asks for one.
    fn mark(&mut self, body: fmt::Arguments<'_>) -> io::Result<()> {
        let text = mark(body, self.mark_nonce());
        self.write_bytes(text.as_bytes())
    }
}

/// `OSC 133 ; body`, with `nonce` if the terminal asks for one.
pub fn mark(body: fmt::Arguments<'_>, nonce: Option<&MarkNonce>) -> String {
    match nonce {
        Some(nonce) => format!("\x1b]133;{body};nonce={}\x07", nonce.0),
        None => format!("\x1b]133;{body}\x07"),
    }
}

/// A backend that captures the bytes a terminal would receive, for tests. It reports `size`, 24×80
/// by default.
#[cfg(test)]
pub(crate) struct CaptureBackend {
    pub written: Vec<u8>,
    pub size: Size,
    pub nonce: Option<MarkNonce>,
}

#[cfg(test)]
impl Default for CaptureBackend {
    fn default() -> Self {
        Self {
            written: Vec::new(),
            size: Size::new(24, 80),
            nonce: None,
        }
    }
}

#[cfg(test)]
impl KohBackend for CaptureBackend {
    fn write_bytes(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.written.extend_from_slice(bytes);
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
    fn mark_nonce(&self) -> Option<&MarkNonce> {
        self.nonce.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marks_carry_the_nonce_the_terminal_asks_for_and_only_a_word_is_one() {
        let marks = |nonce| {
            let mut b = CaptureBackend {
                nonce,
                ..CaptureBackend::default()
            };
            b.mark(format_args!("A")).unwrap();
            b.mark(format_args!("D;1")).unwrap();
            String::from_utf8(b.written).unwrap()
        };
        assert_eq!(marks(None), "\x1b]133;A\x07\x1b]133;D;1\x07");
        assert_eq!(
            marks(MarkNonce::new("ab12")),
            "\x1b]133;A;nonce=ab12\x07\x1b]133;D;1;nonce=ab12\x07"
        );
        for bad in ["", "a;b", "a\x07", &"x".repeat(65)] {
            assert_eq!(MarkNonce::new(bad), None, "{bad:?}");
        }
    }
}
