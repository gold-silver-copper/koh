//! What attaching costs koh: each workload played into a server emulator keeping the default
//! scrollback, then the redraw a client attaching afresh is sent (the screen and up to 1000 rows
//! of history above it, into the user's terminal's own scrollback) encoded as the wire carries
//! it. In process, with no link: the bytes are the messages' before QUIC.

use koh::proto::{encode_shown, MarkText, Shown};
use koh::stream::Piece;
use koh::terminal::{redraw, ServerTerminal, Size};

use crate::workloads::Workload;

/// The scrollback a server keeps by default (`koh serve --scrollback-bytes`), in bytes.
const SCROLLBACK: usize = 8 << 20;

/// The rows of history a client attaching afresh is sent, as koh's server sends them.
const ATTACH_HISTORY: usize = 1000;

/// A workload's redraw: the rows of history it carries, and its bytes.
#[derive(Clone, Copy, Debug, Default)]
pub struct History {
    pub rows: usize,
    pub bytes: u64,
}

pub fn measure(workload: &Workload) -> anyhow::Result<History> {
    let mut emu = ServerTerminal::new(workload.rows, workload.cols, SCROLLBACK)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    for step in &workload.steps {
        if let Some((rows, cols)) = step.resize {
            emu.resize(Size::new(rows, cols));
        }
        emu.process(&step.output);
    }
    let screen = emu.live();
    let mut history = History {
        rows: screen.history_len().min(ATTACH_HISTORY),
        bytes: 0,
    };
    for piece in redraw(screen, emu.title(), ATTACH_HISTORY) {
        let shown = match piece {
            Piece::Out(bytes) => Shown::Out(bytes),
            Piece::Mark(mark) => match MarkText::new(mark) {
                Some(mark) => Shown::Mark(mark),
                None => continue,
            },
        };
        let bytes = encode_shown(&shown).map_err(|e| anyhow::anyhow!("{e}"))?;
        history.bytes = history
            .bytes
            .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
    }
    Ok(history)
}
