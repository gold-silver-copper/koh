#![no_main]
//! Fuzz both directions of the koh/8 shell stream: arbitrary bytes as the client's message stream
//! (the server's parser) and as what a program shows (the client's parser). Both must only return
//! errors on bad input, never panic, and never allocate past their caps.

use koh::proto::{ClientDecoder, ShownDecoder};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The first byte splits the rest into chunks, so the decoders see varied read boundaries.
    let (split, rest) = data
        .split_first()
        .map_or((1, data), |(b, r)| (usize::from(*b).max(1), r));
    let mut client = ClientDecoder::default();
    let mut shown = ShownDecoder::default();
    let (mut client_ok, mut shown_ok) = (true, true);
    for chunk in rest.chunks(split) {
        client.push(chunk);
        shown.push(chunk);
        while client_ok {
            match client.next_msg() {
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(_) => client_ok = false,
            }
        }
        while shown_ok {
            match shown.next_shown() {
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(_) => shown_ok = false,
            }
        }
    }
    let _ = (client.finish(), shown.finish());
});
