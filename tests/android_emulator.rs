//! Opt-in Android-emulator smoke test.
//!
//! This is a thin Rust wrapper around `testing/android/scripts/run.sh` so the emulator tests can be
//! driven through `cargo test` alongside the rest of the suite — but it is **not** part of the
//! default run. It is `#[ignore]`d AND additionally gated on `KOH_ANDROID_EMULATOR=1`, so a normal
//! `cargo test` never touches an emulator. Invoke it explicitly:
//!
//! ```sh
//! KOH_ANDROID_EMULATOR=1 cargo test --test android_emulator -- --ignored --nocapture
//! ```
//!
//! It requires a booted Android emulator + a configured NDK (see `testing/android/README.md`). The
//! script itself skips cleanly (exit 0) if no device is connected, so this test never flakes on a
//! machine without an emulator even when run with `--ignored`.

use std::process::Command;

#[test]
#[ignore = "requires a booted Android emulator + NDK; opt in with KOH_ANDROID_EMULATOR=1"]
fn android_emulator_smoke() {
    if std::env::var_os("KOH_ANDROID_EMULATOR").as_deref() != Some(std::ffi::OsStr::new("1")) {
        eprintln!("skipping: set KOH_ANDROID_EMULATOR=1 to run the Android emulator smoke test");
        return;
    }
    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testing/android/scripts/run.sh"
    );
    let status = Command::new("sh")
        .arg(script)
        .status()
        .expect("failed to launch testing/android/scripts/run.sh");
    assert!(
        status.success(),
        "Android emulator tests failed (see output above); run.sh exited with {status}"
    );
}
