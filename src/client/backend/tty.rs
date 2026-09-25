//! The terminal koh's client paints on: the controlling tty, driven through `rustix::termios`.
//!
//! It supplies only the platform primitives — raw mode, the window size, and a byte sink. Every
//! escape sequence comes from [`KohBackend`]'s provided methods.

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::os::fd::AsFd;

use rustix::termios::{self, OptionalActions, Termios};

use super::KohBackend;

/// Output is buffered and flushed once per frame.
const BUF_SIZE: usize = 64 * 1024;

/// The controlling terminal: stdout when it is a terminal, else `/dev/tty`.
pub struct Tty {
    out: BufWriter<File>,
    /// The terminal's mode when koh started, restored on leaving raw mode and on drop.
    original: Termios,
}

impl Tty {
    /// Open the terminal and record its current mode. Does not enter raw mode.
    pub fn new() -> io::Result<Self> {
        let stdout = io::stdout();
        let file = if termios::isatty(stdout.as_fd()) {
            File::from(stdout.as_fd().try_clone_to_owned()?)
        } else {
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/tty")?
        };
        let original = termios::tcgetattr(&file)?;
        Ok(Self {
            out: BufWriter::with_capacity(BUF_SIZE, file),
            original,
        })
    }
}

impl KohBackend for Tty {
    fn write_bytes(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.out.write_all(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }

    fn enter_raw_mode(&mut self) -> io::Result<()> {
        let mut raw = termios::tcgetattr(self.out.get_ref())?;
        raw.make_raw();
        termios::tcsetattr(self.out.get_ref(), OptionalActions::Flush, &raw)?;
        Ok(())
    }

    fn leave_raw_mode(&mut self) -> io::Result<()> {
        termios::tcsetattr(self.out.get_ref(), OptionalActions::Now, &self.original)?;
        Ok(())
    }

    fn size(&self) -> io::Result<(u16, u16)> {
        let size = termios::tcgetwinsize(self.out.get_ref())?;
        let (mut rows, mut cols) = (size.ws_row, size.ws_col);
        // Over a serial line the ioctl may report zero; fall back to LINES/COLUMNS, as vim does.
        let env = |name: &str| std::env::var(name).ok().and_then(|v| v.parse::<u16>().ok());
        if rows == 0 {
            rows = env("LINES").unwrap_or(0);
        }
        if cols == 0 {
            cols = env("COLUMNS").unwrap_or(0);
        }
        if rows == 0 || cols == 0 {
            return Err(io::Error::other(
                "cannot read a non-zero terminal size from the ioctl or LINES/COLUMNS",
            ));
        }
        Ok((rows, cols))
    }
}

impl Drop for Tty {
    fn drop(&mut self) {
        // `BackendTerminal::drop` already leaves raw mode; this also covers a `Tty` dropped before
        // it was wrapped, so the user's terminal is never left raw.
        let _ = self.out.flush();
        let _ = self.leave_raw_mode();
    }
}
