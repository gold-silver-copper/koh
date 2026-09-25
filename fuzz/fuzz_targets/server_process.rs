#![no_main]
//! Fuzz the host-side emulator input path: arbitrary bytes (the hosted program's output — not
//! wire-controlled, but a hostile or buggy app can emit anything) -> `ServerTerminal::process`,
//! then the snapshot and host replies the server reads. Must never panic (fux-vt is panic-free by
//! construction; this checks it stays that way under koh's options).

use koh_core::terminal::ServerTerminal;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(mut t) = ServerTerminal::new(24, 80, 100) else {
        return;
    };
    // Split the input into a few chunks so sequences straddle `process` calls.
    let n = data.len().max(1);
    for chunk in data.chunks((n / 3).max(1)) {
        t.process(chunk);
        let _ = t.take_host_replies();
    }
    let snap = t.snapshot();
    let _ = snap.screen().contents();
});
