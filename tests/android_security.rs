//! Opt-in Android-emulator SECURITY suite entry point.
//!
//! A thin Rust wrapper around `testing/android/scripts/run-security.sh` so the security tests can be
//! driven through `cargo test` — but it is NOT part of the default run. It is `#[ignore]`d AND gated
//! on `KOH_ANDROID_EMULATOR=1`, so a normal `cargo test` never touches an emulator. It requires a
//! booted Android emulator + a configured NDK (see `testing/android/README.md`), and the
//! cross-compiled malicious-peer helper under `testing/android/evil-peer/` for the wire-level demos
//! (the scripts SKIP cleanly if it isn't built). Invoke explicitly:
//!
//! ```sh
//! KOH_ANDROID_EMULATOR=1 cargo test --test android_security -- --ignored --nocapture
//! ```
//!
//! Each `sec-*.sh` asserts the SECURE behavior, so the suite FAILS against unpatched koh
//! (demonstrating the audit findings — see `testing/android/RED-security-run.txt`) and PASSES once
//! they're fixed (`testing/android/GREEN-security-run.txt`). The script skips cleanly (exit 0) with
//! no device, so even `--ignored` never flakes without one.

use std::process::Command;

#[test]
#[ignore = "requires a booted Android emulator + NDK; opt in with KOH_ANDROID_EMULATOR=1"]
fn android_security_suite() {
    if std::env::var_os("KOH_ANDROID_EMULATOR").as_deref() != Some(std::ffi::OsStr::new("1")) {
        eprintln!("skipping: set KOH_ANDROID_EMULATOR=1 to run the Android security suite");
        return;
    }
    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testing/android/scripts/run-security.sh"
    );
    let status = Command::new("sh")
        .arg(script)
        .status()
        .expect("failed to launch testing/android/scripts/run-security.sh");
    assert!(
        status.success(),
        "Android security suite failed (a finding is present or unverified); \
         run-security.sh exited with {status}"
    );
}
