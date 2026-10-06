#![no_main]
//! Fuzz the client's start-up probe: arbitrary bytes as the user's terminal's answers and keys
//! typed meanwhile, read in pieces. It must never panic, give back nothing it was not given, and
//! keep at most what it was asked (16 palette entries).

use koh::client::probe::Replies;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (split, rest) = data.split_first().map_or((1, data), |(b, r)| (usize::from(*b).max(1), r));
    let mut replies = Replies::default();
    for chunk in rest.chunks(split) {
        replies.push(chunk);
    }
    assert!(replies.colours().palette.len() <= koh::events::PALETTE);
    let _ = (replies.done(), replies.kitty(), replies.underline_styles());
    assert!(replies.typed().len() <= rest.len());
});
