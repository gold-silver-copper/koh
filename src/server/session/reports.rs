//! When a session reports what its program is doing ([`Report`]), so that a terminal driving the
//! client (fux) sees a remote program wait for input as it sees a local one. Without I/O: the
//! session probes, and gives the time and what the probe said.
//!
//! A report is made:
//!
//! - after input is written to the program's terminal, even of an unchanged state: a terminal
//!   trusts a report only if it came after its own last input;
//! - when the state changes, probed every [`POLL`] while a client is attached;
//! - after the shell marks a command's start or end (OSC 133 `C`, `D`) and after a resize, so a
//!   fresh state rides with every command boundary. One after a mark follows the mark on the
//!   client's stream, at once.
//!
//! An unchanged state is never reported again within [`SPACING`] of the last report, but after
//! a mark: one owed sooner waits for it.

use std::time::Duration;

use tokio::time::Instant;

use crate::terminal::Activity;

/// A report of the program's [`Activity`], numbered: each report is a new number, even of an
/// unchanged state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Report {
    /// Which report it is: the session's count of them, from 1.
    pub(super) n: u64,
    pub(super) activity: Activity,
}

/// How often the program is probed for a change while a client is attached: about as often as
/// fux probes a local program.
pub(super) const POLL: Duration = Duration::from_millis(20);

/// The least time between two reports of an unchanged state.
pub(super) const SPACING: Duration = Duration::from_millis(10);

/// What a session reported, and whether it owes a report.
#[derive(Debug, Default)]
pub(super) struct Reports {
    /// The last report, and when it was made.
    last: Option<(Report, Instant)>,
    /// A report is owed (input was written, or the screen resized), whatever the state.
    owed: bool,
}

/// Why the program is probed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Probe {
    /// To see whether its state changed, or to make an owed report.
    Poll,
    /// The shell marked a command's start or end: reported whatever the state.
    Marked,
}

impl Reports {
    /// The last report, if any was made.
    pub(super) fn last(&self) -> Option<Report> {
        self.last.map(|(report, _)| report)
    }

    /// A report is owed: input was written to the program, or its terminal resized.
    pub(super) fn owe(&mut self) {
        self.owed = true;
    }

    /// When to probe for the report owed, if one is: at `now`, or once [`SPACING`] passed since
    /// the last.
    pub(super) fn due(&self, now: Instant) -> Option<Instant> {
        self.owed.then(|| {
            self.last
                .and_then(|(_, at)| at.checked_add(SPACING))
                .map_or(now, |spaced| spaced.max(now))
        })
    }

    /// The program was probed at `now`, for `why`, and is doing `activity`: the report to make, if
    /// one is due.
    pub(super) fn probed(
        &mut self,
        now: Instant,
        why: Probe,
        activity: Activity,
    ) -> Option<Report> {
        let changed = self.last.is_none_or(|(last, _)| last.activity != activity);
        let spaced = self.due(now).is_some_and(|due| due <= now);
        if !(changed || spaced || why == Probe::Marked) {
            return None;
        }
        let n = self.last.map_or(1, |(last, _)| last.n.saturating_add(1));
        let report = Report { n, activity };
        self.last = Some((report, now));
        self.owed = false;
        Some(report)
    }
}

#[cfg(test)]
mod tests {
    use super::{Activity, Probe, Reports, SPACING};
    use tokio::time::Instant;

    #[test]
    fn reports_follow_input_changes_and_marks_spaced_when_unchanged() {
        let t0 = Instant::now();
        let ms = |n| t0 + std::time::Duration::from_millis(n);
        let mut r = Reports::default();
        let n = |report: Option<super::Report>| report.map(|r| r.n);
        assert_eq!(r.due(t0), None, "nothing owed");
        // The first probe reports, whatever it says; an unchanged poll then reports nothing.
        assert_eq!(n(r.probed(t0, Probe::Poll, Activity::Reading)), Some(1));
        assert_eq!(r.probed(ms(20), Probe::Poll, Activity::Reading), None);
        // Input written: owed, and made at once, unchanged as it is.
        r.owe();
        assert_eq!(r.due(ms(30)), Some(ms(30)));
        assert_eq!(n(r.probed(ms(30), Probe::Poll, Activity::Reading)), Some(2));
        assert_eq!(r.due(ms(30)), None, "made");
        // More input within the spacing: owed until it passed, then made.
        r.owe();
        assert_eq!(r.due(ms(33)), Some(ms(30) + SPACING));
        assert_eq!(r.probed(ms(33), Probe::Poll, Activity::Reading), None);
        assert_eq!(n(r.probed(ms(40), Probe::Poll, Activity::Reading)), Some(3));
        // A change is reported at once, spaced or not.
        assert_eq!(n(r.probed(ms(41), Probe::Poll, Activity::Busy)), Some(4));
        // A mark is reported at once, unchanged and within the spacing, and makes the owed one.
        r.owe();
        let marked = r.probed(ms(42), Probe::Marked, Activity::Busy);
        assert_eq!(marked.map(|r| (r.n, r.activity)), Some((5, Activity::Busy)));
        assert_eq!(r.due(ms(42)), None);
        assert_eq!(r.last(), marked);
    }
}
