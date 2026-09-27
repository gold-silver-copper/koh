#![no_main]
//! Fuzz the untrusted SERVER->CLIENT screen-apply path — the highest-value attacker surface: a
//! server (or anyone who compromised one) controls every `ScreenDiff` the client applies.
//!
//! Arbitrary bytes are decoded as a `ScreenDiff` exactly as a frame carries it (postcard), then
//! applied to a blank screen and to one with content. `apply` validates shifts, rows, runs and
//! cells and drops a malformed frame whole, so it must NEVER panic, and must always leave a grid
//! within the dimension clamp whose rows are exactly as wide as the screen, with the cursor in
//! range. The body mirrors the in-tree `apply_is_panic_free_and_holds_invariants` proptest,
//! extended to coverage-guided fuzzing of the encoding.
//!
//! Random bytes rarely decode as valid row shifts, so the same bytes are also read as a list of
//! raw `(top, len, by)` shifts and put, when they are valid, on a real diff that scrolls.

use std::num::{NonZeroI16, NonZeroU16};

use koh::terminal::{ScreenDiff, Shift, Shifts, Size, TerminalScreen, MAX_DIM, MIN_DIM};
use libfuzzer_sys::fuzz_target;

fn check(screen: &TerminalScreen) {
    let Size { rows, cols } = screen.size();
    assert!((MIN_DIM..=MAX_DIM).contains(&rows) && (MIN_DIM..=MAX_DIM).contains(&cols));
    for row in 0..rows {
        assert_eq!(
            screen.screen().row(row).map(<[_]>::len),
            Some(usize::from(cols))
        );
    }
    let (crow, ccol) = screen.screen().cursor_position();
    assert!(crow < rows && ccol <= cols);
}

/// The fuzz input's leading `(top, len, by)` triples as shifts, if they are valid ones.
fn shifts(data: &[u8]) -> Option<Shifts> {
    let (raw, _) = postcard::take_from_bytes::<Vec<(u16, u16, i16)>>(data).ok()?;
    let shifts = raw
        .into_iter()
        .map(|(top, len, by)| {
            Some(Shift {
                top,
                len: NonZeroU16::new(len)?,
                by: NonZeroI16::new(by)?,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    Shifts::new(shifts)
}

fuzz_target!(|data: &[u8]| {
    let prior = TerminalScreen::from_bytes(24, 80, "prior 日本 \x1b[31mscreen\x1b[m".as_bytes());
    if let Ok(diff) = postcard::from_bytes::<ScreenDiff>(data) {
        for mut screen in [TerminalScreen::default(), prior.clone()] {
            screen.apply(&diff); // must never panic — the libFuzzer assertion
            check(&screen);
        }
    }
    if let Some(shifts) = shifts(data) {
        let scrolled = TerminalScreen::from_bytes(24, 80, "prior 日本\r\n\r\nscrolled\r\n".as_bytes());
        let mut diff = scrolled.diff_from(&prior);
        diff.shifts = shifts;
        let mut screen = prior;
        screen.apply(&diff);
        check(&screen);
    }
});
