#![no_main]
//! Fuzz the untrusted SERVER->CLIENT screen-apply path — the highest-value attacker surface: a
//! server (or anyone who compromised one) controls every `ScreenDiff` the client applies.
//!
//! Arbitrary bytes are decoded as a `ScreenDiff` exactly as the transport does (postcard), then
//! applied to a blank screen and to one with content. `apply` validates rows, runs and cells and
//! drops a malformed frame whole, so it must NEVER panic, and must always leave a grid within the
//! dimension clamp whose rows are exactly as wide as the screen, with the cursor in range. The body
//! mirrors the in-tree `apply_is_panic_free_and_holds_invariants` proptest, extended to
//! coverage-guided fuzzing of the encoding.

use koh::ssp::SyncState;
use koh::terminal::{ScreenDiff, TerminalScreen, MAX_DIM, MIN_DIM};
use libfuzzer_sys::fuzz_target;

fn check(screen: &TerminalScreen) {
    let (rows, cols) = screen.size();
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

fuzz_target!(|data: &[u8]| {
    let Ok(diff) = postcard::from_bytes::<ScreenDiff>(data) else {
        return;
    };
    for mut screen in [
        TerminalScreen::default(),
        TerminalScreen::from_bytes(24, 80, "prior 日本 \x1b[31mscreen\x1b[m".as_bytes()),
    ] {
        screen.apply(&diff); // must never panic — the libFuzzer assertion
        check(&screen);
    }
});
