#![no_main]
//! Fuzz the untrusted wire decode path: arbitrary bytes -> `Instruction::decode` (bounded DEFLATE
//! inflate + postcard deserialization). This is the anti-decompression-bomb / malformed-frame surface
//! (KOH-02, K-06/K-12). It must only ever return `Err` on bad input — never panic, never OOM (the
//! inflate ceiling bounds output). A `Fragment::decode` pass first exercises the fixed-header parse.

use koh::wire::{Fragment, Instruction};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The datagram framing parse (header + per-fragment payload bound).
    let _ = Fragment::decode(data);
    // The reassembled-instruction decode: inflate (bounded) + protocol-version check + postcard.
    let _ = Instruction::decode(data);
});
