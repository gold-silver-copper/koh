//! The `qwertty` terminal backend — an optional, off-by-default alternate (feature
//! `backend-qwertty`) built on joshka's `qwertty` terminal crate.
//!
//! Like the other backends, koh's ANSI output is byte-identical (it all comes from [`KohBackend`]'s
//! provided methods); `qwertty` supplies only the platform primitives. It owns the controlling
//! terminal directly (`/dev/tty`) rather than stdout, and its `Terminal` already restores cooked
//! mode on drop — the generic `BackendTerminal` teardown still calls `leave_raw_mode` explicitly, so
//! restoration is both explicit and defended in depth. Build with
//! `--no-default-features --features backend-qwertty`.

use std::io::{self, Write};

use qwertty::Terminal;

use super::KohBackend;

/// A `qwertty`-backed terminal that owns the controlling terminal device (`/dev/tty`).
///
/// `qwertty`'s `Result`/`Error` are mapped to `io::Result`/`io::Error` at this boundary (the error
/// keeps its source chain via `io::Error::other`), so nothing above the backend seam sees a
/// qwertty-specific type. Output is buffered (like the other backends — `qwertty::Terminal` writes
/// straight to the device otherwise) so a frame's many small writes are one syscall batch, flushed
/// per frame; the raw-mode / size ioctls reach through the buffer via `get_ref`.
pub struct QwerttyBackend {
    out: io::BufWriter<Terminal>,
}

impl QwerttyBackend {
    /// Open the controlling terminal (`/dev/tty`). Does not enter raw mode or the alternate screen —
    /// the generic `BackendTerminal::enter` sequences those through the trait.
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            out: io::BufWriter::new(Terminal::open().map_err(io::Error::other)?),
        })
    }
}

impl KohBackend for QwerttyBackend {
    fn write_bytes(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.out.write_all(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }

    fn enter_raw_mode(&mut self) -> io::Result<()> {
        self.out.get_ref().set_raw_mode().map_err(io::Error::other)
    }

    fn leave_raw_mode(&mut self) -> io::Result<()> {
        self.out
            .get_ref()
            .set_cooked_mode()
            .map_err(io::Error::other)
    }

    fn size(&self) -> io::Result<(u16, u16)> {
        // qwertty reports `(columns, rows)`; koh uses `(rows, cols)`.
        let size = self.out.get_ref().size().map_err(io::Error::other)?;
        Ok((size.rows(), size.columns()))
    }
}
