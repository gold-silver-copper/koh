//! The `termina` terminal backend — the default (feature `backend-termina`) and the only one
//! shipped in `cargo install koh`.
//!
//! This is what confines `termina` to the backend module: it reduces `termina` to a cross-platform
//! terminal handle (raw-mode control, a size query, and an `io::Write` sink). Every escape sequence
//! koh paints now comes from [`KohBackend`]'s provided methods, so `termina`'s escape DSL
//! (`Csi`/`Sgr`/`ColorSpec`) is no longer on the render path at all.

use std::io::{self, Write};

use termina::{PlatformTerminal, Terminal as _};

use super::KohBackend;

/// A `termina` [`PlatformTerminal`]. Raw mode and the alternate screen are sequenced by the generic
/// [`BackendTerminal`](crate::client::BackendTerminal); this type supplies only the primitives.
pub struct TerminaBackend {
    term: PlatformTerminal,
}

impl TerminaBackend {
    /// Acquire the platform terminal. Does **not** enter raw mode or the alternate screen — the
    /// generic `BackendTerminal::enter` does that through the trait, so the enter/leave sequences
    /// live in exactly one place across all backends.
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            term: PlatformTerminal::new()?,
        })
    }
}

impl KohBackend for TerminaBackend {
    fn write_bytes(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.term.write_all(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        Write::flush(&mut self.term)
    }

    fn enter_raw_mode(&mut self) -> io::Result<()> {
        self.term.enter_raw_mode()
    }

    fn leave_raw_mode(&mut self) -> io::Result<()> {
        self.term.enter_cooked_mode()
    }

    fn size(&self) -> io::Result<(u16, u16)> {
        let d = self.term.get_dimensions()?;
        Ok((d.rows, d.cols))
    }
}
