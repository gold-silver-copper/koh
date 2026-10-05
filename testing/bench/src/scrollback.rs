//! What a full scrollback costs koh: each workload played into a server emulator keeping the
//! default scrollback, then every history row it keeps fetched as a client's scrollback view
//! fetches them, in requests of the most rows one may ask for, and the compressed streams counted.
//! In process, with no link: the bytes are those the history streams carry.

use koh::proto::encode_history;
use koh::terminal::{HistoryRequest, ServerTerminal, Size, MAX_HISTORY_ROWS};

use crate::workloads::Workload;

/// The scrollback a server keeps by default (`koh serve --scrollback`).
const SCROLLBACK: usize = 1000;

/// A workload's history: the rows the server keeps at its end, and the bytes to fetch them all.
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
    let mark = emu.snapshot().history();
    let mut history = History::default();
    let Some(oldest) = mark.oldest() else {
        return Ok(history);
    };
    let mut newest = mark.newest;
    while newest >= oldest {
        let reply = emu.history(HistoryRequest {
            newest,
            count: MAX_HISTORY_ROWS,
        });
        if reply.rows.is_empty() {
            break;
        }
        history.rows = history.rows.saturating_add(reply.rows.len());
        let bytes = encode_history(&reply).map_err(|e| anyhow::anyhow!("{e}"))?;
        history.bytes = history
            .bytes
            .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        let fetched = u64::try_from(reply.rows.len()).unwrap_or(u64::MAX);
        let Some(next) = newest.checked_sub(fetched) else {
            break;
        };
        newest = next;
    }
    Ok(history)
}
