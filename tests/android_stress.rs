//! Opt-in Android-emulator STRESS suite entry point.
//!
//! A thin Rust wrapper around `testing/android/scripts/run-stress.sh` so the stress suite can be
//! driven through `cargo test` — but it is NOT part of the default run. It is `#[ignore]`d AND gated
//! on `KOH_ANDROID_EMULATOR=1`, so a normal `cargo test` never touches an emulator. It requires a
//! booted Android emulator + a configured NDK (see `testing/android/README.md`). Invoke explicitly:
//!
//! ```sh
//! KOH_ANDROID_EMULATOR=1 cargo test --test android_stress -- --ignored --nocapture
//! # heavy soak:
//! KOH_ANDROID_EMULATOR=1 KOH_STRESS_LEVEL=full cargo test --test android_stress -- --ignored --nocapture
//! ```
//!
//! The script skips cleanly (exit 0) with no device, so even `--ignored` never flakes without one.

use std::process::Command;

#[test]
#[ignore = "requires a booted Android emulator + NDK; opt in with KOH_ANDROID_EMULATOR=1"]
fn android_stress_suite() {
    if std::env::var_os("KOH_ANDROID_EMULATOR").as_deref() != Some(std::ffi::OsStr::new("1")) {
        eprintln!("skipping: set KOH_ANDROID_EMULATOR=1 to run the Android stress suite");
        return;
    }
    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testing/android/scripts/run-stress.sh"
    );
    let status = Command::new("sh")
        .arg(script)
        .status()
        .expect("failed to launch testing/android/scripts/run-stress.sh");
    assert!(
        status.success(),
        "Android stress suite failed (see output above); run-stress.sh exited with {status}"
    );
}
