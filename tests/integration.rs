//! In-process end-to-end integration + chaos convergence (formerly the `xtask` crate).
//!
//! Wires the client and server transports through the deterministic chaotic link and asserts the
//! states converge end-to-end under loss, and that the predictor confirms/suppresses against real
//! frames. The driver lives in `koh::sim`; the manual `--loss` explorer is `examples/chaos.rs`.

// Integration test: a failed unwrap/expect/assert IS the test failing.
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "integration test code; panics are assertion failures"
)]

use koh::sim::{run_predictor_reconciliation, run_session};

#[test]
fn integration_converges_clean_link() {
    run_session(0.0, 1).assert_ok().unwrap();
}

#[test]
fn integration_converges_lossy_link() {
    for seed in 1..6 {
        run_session(0.3, seed)
            .assert_ok()
            .unwrap_or_else(|e| panic!("seed {seed}: {e}"));
    }
}

#[test]
fn predictor_reconciles_against_real_screen() {
    run_predictor_reconciliation().unwrap();
}
