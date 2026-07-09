//! The `crossterm` terminal backend — an optional, off-by-default alternate (feature
//! `backend-crossterm`) that proves the [`KohBackend`] seam with a second, independently-maintained
//! terminal crate.
//!
//! koh's ANSI output is byte-identical to the `termina` path (it all comes from [`KohBackend`]'s
//! provided methods); `crossterm` supplies only raw-mode control, the size ioctl, and a stdout sink.
//! Build with `--no-default-features --features backend-crossterm`.

use std::io::{self, Write};

use super::KohBackend;

/// A `crossterm`-backed terminal that writes escapes to a buffered stdout.
///
/// Raw mode is toggled with crossterm's cross-platform ioctls; nothing else about crossterm's API is
/// used, so the emitted bytes match every other backend.
pub struct CrosstermBackend {
    /// Buffered so a frame's many small writes are one syscall batch, flushed per frame.
    out: io::BufWriter<io::Stdout>,
    /// Whether *we* put the terminal into raw mode, so teardown only undoes what we did.
    raw: bool,
}

impl CrosstermBackend {
    /// Acquire stdout. Does not touch raw mode or the alternate screen — the generic
    /// `BackendTerminal::enter` sequences those through the trait.
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            out: io::BufWriter::new(io::stdout()),
            raw: false,
        })
    }
}

impl KohBackend for CrosstermBackend {
    fn write_bytes(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.out.write_all(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }

    fn enter_raw_mode(&mut self) -> io::Result<()> {
        crossterm::terminal::enable_raw_mode()?;
        self.raw = true;
        Ok(())
    }

    fn leave_raw_mode(&mut self) -> io::Result<()> {
        if self.raw {
            crossterm::terminal::disable_raw_mode()?;
            self.raw = false;
        }
        Ok(())
    }

    fn size(&self) -> io::Result<(u16, u16)> {
        // crossterm reports `(columns, rows)`; koh uses `(rows, cols)` everywhere.
        let (cols, rows) = crossterm::terminal::size()?;
        Ok((rows, cols))
    }
}

impl Drop for CrosstermBackend {
    fn drop(&mut self) {
        // Defense in depth: `BackendTerminal::drop` already calls `leave_raw_mode`, but crossterm's
        // raw mode is process-global and not RAII, so if this backend is ever dropped by another
        // path we still un-raw the tty rather than leave the user's shell echo-off.
        if self.raw {
            let _ = crossterm::terminal::disable_raw_mode();
        }
    }
}
