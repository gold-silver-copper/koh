//! The server's terminal.
//!
//! A session's emulator ([`ServerTerminal`]) answers its program's questions and keeps its screen;
//! a client attaching is sent the [`redraw`] of that screen; [`Activity`] is the program's state
//! as probed.

use serde::{Deserialize, Serialize};

mod redraw;
mod server;

pub use redraw::{redraw, RESET};
pub use server::{ServerTerminal, IDENTITY, OPTIONS};

/// A terminal's geometry: `rows` lines of `cols` cells each. On the wire it is its two `u16`s,
/// rows first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Size {
    pub rows: u16,
    pub cols: u16,
}

impl Size {
    pub const fn new(rows: u16, cols: u16) -> Self {
        Self { rows, cols }
    }
}

/// How the program's PTY takes typed keys: whether the kernel echoes them, and edits lines.
///
/// Line mode without echo is a password prompt (`getpass`, `read -s`, sudo, ssh, passwd); neither
/// is a line editor or a full-screen program, which echo for themselves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TtyModes {
    pub echo: bool,
    pub line: bool,
}

impl TtyModes {
    /// A password prompt: lines read without echo. Nothing typed may be shown.
    pub const fn password(self) -> bool {
        self.line && !self.echo
    }
}

/// Default screen geometry, before a client says its own.
pub const DEFAULT_SIZE: Size = Size::new(24, 80);

/// Bounds on a peer-controlled geometry. A grid is allocated whole, so every size a peer sends
/// passes through [`clamp_dims`] first: 65000×65000 would be billions of cells. 1000×1000 dwarfs
/// any display.
pub const MIN_DIM: u16 = 2;
pub const MAX_DIM: u16 = 1000;

/// Most characters in a window title, as mosh caps them.
pub(crate) const MAX_TITLE_LEN: usize = 256;

/// Clamp a peer-supplied size into `[MIN_DIM, MAX_DIM]` on both axes: the one gate every resize
/// passes before a grid is built.
#[must_use]
pub fn clamp_dims(size: Size) -> Size {
    Size {
        rows: size.rows.clamp(MIN_DIM, MAX_DIM),
        cols: size.cols.clamp(MIN_DIM, MAX_DIM),
    }
}

/// Dimensions accepted for a running terminal, shared by the emulator and kernel PTY.
pub(crate) fn host_size(size: Size) -> fux_vt::Size {
    use std::num::NonZeroU16;
    let Size { rows, cols } = clamp_dims(size);
    fux_vt::Size::from((
        NonZeroU16::new(rows).unwrap_or(NonZeroU16::MIN),
        NonZeroU16::new(cols).unwrap_or(NonZeroU16::MIN),
    ))
}

/// What the program in the foreground of the session's terminal is doing, as the server probed
/// it: fuxix's `Activity`, on koh's wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Activity {
    /// Blocked reading the terminal with no time limit: it waits for input.
    Reading,
    /// Waiting on the terminal with a time limit, so it may draw again on its own.
    Polling,
    /// Blocked on something else: the network, a pipe, another program.
    Waiting,
    /// Running, sleeping on a timer, or starting.
    Busy,
    /// Every thread waits on something the system does not name (macOS).
    Idle,
    /// The system does not say.
    Unknown,
}

impl From<fuxix::process::Activity> for Activity {
    fn from(activity: fuxix::process::Activity) -> Self {
        use fuxix::process::Activity as Probed;
        match activity {
            Probed::Reading => Self::Reading,
            Probed::Polling => Self::Polling,
            Probed::Waiting => Self::Waiting,
            Probed::Busy => Self::Busy,
            Probed::Idle => Self::Idle,
            Probed::Unknown => Self::Unknown,
        }
    }
}

impl Activity {
    /// The state as `OSC 133 ; S ; activity=` names it.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Reading => "reading",
            Self::Polling => "polling",
            Self::Waiting => "waiting",
            Self::Busy => "busy",
            Self::Idle => "idle",
            Self::Unknown => "unknown",
        }
    }
}

/// The text of `rows`, soft-wrapped ones joined to the next, each line's trailing blanks dropped,
/// from column `from` of the first to column `to` of the last (both inclusive), at most `max`
/// bytes (the end kept).
pub(crate) fn text_of<'a>(
    rows: impl Iterator<Item = fux_vt::Row<'a>>,
    from: usize,
    to: Option<usize>,
    max: usize,
) -> String {
    let rows: Vec<fux_vt::Row<'a>> = rows.collect();
    let mut text = String::new();
    let mut line = String::new();
    let last = rows.len().saturating_sub(1);
    for (n, row) in rows.iter().enumerate() {
        let start = if n == 0 { from } else { 0 };
        let end = if n == last {
            to.unwrap_or(usize::MAX)
        } else {
            usize::MAX
        };
        for (_, glyph) in row.copied(start, end) {
            line.push_str(glyph);
        }
        if !row.wrapped() || n == last {
            text.push_str(line.trim_end());
            text.push('\n');
            line.clear();
        }
    }
    if text.len() > max {
        let mut cut = text.len().saturating_sub(max);
        while !text.is_char_boundary(cut) {
            cut = cut.saturating_add(1);
        }
        text = text.split_off(cut);
    }
    text
}
