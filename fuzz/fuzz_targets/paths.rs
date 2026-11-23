#![no_main]

#[path = "../entry.rs"]
mod entry;

libfuzzer_sys::fuzz_target!(|data: &[u8]| entry::paths(data));
