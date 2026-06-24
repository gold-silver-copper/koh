#![no_main]
//! Fuzz the untrusted SERVER->CLIENT screen-apply path — the highest-value attacker surface, since
//! `vt100` (which parses the server-controlled escape stream) is a dependency outside koh's
//! `forbid(unsafe)` + denied-panic-lint coverage.
//!
//! `TerminalScreen::apply` CONTAINS vt100 panics (`process_contained` wraps the parser in
//! `catch_unwind`), so this target asserts the containment HOLDS: `apply` must NEVER panic on ANY
//! input, and must leave the screen within the dimension clamp. A crash here means the containment
//! failed (a koh bug); a contained vt100 panic underneath is invisible to the fuzzer (by design).
//! The body mirrors the in-tree `apply_is_panic_free_and_holds_invariants` proptest, extended to
//! coverage-guided fuzzing of the real vt100 escape grammar.

use koh::ssp::SyncState;
use koh::terminal::{ScreenDiff, TerminalScreen};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // First 4 bytes (if present) optionally drive a resize (exercising the repaint-rebuild branch);
    // the remainder is the vt100 escape stream (exercising the incremental branch). Both reach vt100.
    let (head, vt) = data.split_at(data.len().min(4));
    let resize = if head.len() == 4 {
        Some((
            u16::from_le_bytes([head[0], head[1]]),
            u16::from_le_bytes([head[2], head[3]]),
        ))
    } else {
        None
    };
    let diff = ScreenDiff {
        resize,
        echo_ack: 0,
        title: None,
        icon: None,
        clipboard: None,
        bell_count: 0,
        exit_code: None,
        vt: vt.to_vec(),
    };
    let mut screen = TerminalScreen::default();
    screen.apply(&diff); // must never panic — the libFuzzer assertion
});
