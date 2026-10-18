//! The shell's marks (OSC 133) as the screen carries them: which rows start a prompt, in each
//! row's [`RowFlags`], and what the marks say of the shell's commands, placed on the screen
//! ([`Commands`]), so that the client can mark what it paints for the user's terminal; and the
//! server's report of what the session's program is doing ([`Report`]), which the client writes
//! as a mark of the same family (`OSC 133 ; S`).

use fux_vt::RowId;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use super::Size;

/// A row's flags: whether it soft-wraps into the next, and whether a shell's prompt starts on it
/// (`OSC 133 ; A`). One byte on the wire, a bit each; decoding refuses any other bit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RowFlags {
    pub wrapped: bool,
    pub prompt: bool,
}

impl RowFlags {
    const WRAPPED: u8 = 1;
    const PROMPT: u8 = 2;

    /// The flags of the live row `row`; none for no row.
    pub(super) fn of(row: Option<&fux_vt::Row<'_>>) -> Self {
        Self {
            wrapped: row.is_some_and(fux_vt::Row::wrapped),
            prompt: row.is_some_and(fux_vt::Row::starts_prompt),
        }
    }

    const fn bits(self) -> u8 {
        (if self.wrapped { Self::WRAPPED } else { 0 })
            | (if self.prompt { Self::PROMPT } else { 0 })
    }
}

impl Serialize for RowFlags {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(self.bits())
    }
}

impl<'de> Deserialize<'de> for RowFlags {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bits = u8::deserialize(deserializer)?;
        if bits & !(Self::WRAPPED | Self::PROMPT) != 0 {
            return Err(de::Error::invalid_value(
                de::Unexpected::Unsigned(u64::from(bits)),
                &"row flags within 0b11",
            ));
        }
        Ok(Self {
            wrapped: bits & Self::WRAPPED != 0,
            prompt: bits & Self::PROMPT != 0,
        })
    }
}

/// A place on the screen a frame shows, `(row, col)` as the cursor's.
pub type Place = (u16, u16);

/// What the shell's marks say of its commands, placed on the screen.
///
/// The marks are `OSC 133 ; C` where a command's output starts and `D ; status` where it ends. A
/// place the screen does not show (scrolled into history, or on the main screen while the
/// alternate one is shown) is its top left, where what the screen shows of that output begins.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commands {
    /// How many commands have ended, counted by the session's terminal: a new one is a new count.
    pub finished: u64,
    /// The status the last one ended with, if the shell said.
    pub status: Option<i32>,
    /// Where the last one's output began and where it ended.
    pub output: Option<(Place, Place)>,
    /// Where the output of the command running began, while one runs.
    pub running: Option<Place>,
}

impl Commands {
    /// What `screen`'s marks say, placed by `index`, the live index of a row by its id.
    pub(super) fn of(screen: &fux_vt::Screen, index: impl Fn(RowId) -> Option<u16>) -> Self {
        let commands = screen.commands();
        // The marks are the main screen's rows.
        let main = !screen.mode(fux_vt::Mode::AlternateScreen);
        let place = |mark: fux_vt::CommandMark| {
            main.then(|| index(mark.row))
                .flatten()
                .map_or((0, 0), |row| (row, mark.col))
        };
        Self {
            finished: commands.finished,
            status: commands.last_status,
            output: (commands.last_output).map(|(start, end)| (place(start), place(end))),
            running: commands.output_start.map(place),
        }
    }

    /// These commands on a screen of `size`, every place within it (a peer's places are anything).
    #[must_use]
    pub(super) fn within(self, size: Size) -> Self {
        let place = |(row, col): Place| (row.min(size.rows.saturating_sub(1)), col.min(size.cols));
        Self {
            output: self.output.map(|(start, end)| (place(start), place(end))),
            running: self.running.map(place),
            ..self
        }
    }

    /// These commands as a view `offset` rows back into history shows them, `size` large: each
    /// place `offset` rows lower, within it.
    #[must_use]
    pub(super) fn scrolled(self, offset: usize, size: Size) -> Self {
        let down = u16::try_from(offset).unwrap_or(u16::MAX);
        let place = |(row, col): Place| (row.saturating_add(down), col);
        Self {
            output: self.output.map(|(start, end)| (place(start), place(end))),
            running: self.running.map(place),
            ..self
        }
        .within(size)
    }
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

/// The server's report of the program's [`Activity`], numbered by the session: each report is a
/// new number, even of an unchanged state, so that the client tells every one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    /// Which report it is: the session's count of them, from 1.
    pub n: u64,
    pub activity: Activity,
}
