#![no_main]
//! Fuzz both directions of the koh/3 wire decode: arbitrary bytes as the client's message stream
//! (the server's parser) and as a frame's stream contents (the client's parser: bounded inflate
//! plus postcard). Both must only return errors on bad input, never panic, and never allocate past
//! their caps.

use koh::proto::{decode_frame, ClientDecoder};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The first byte splits the rest into chunks, so the decoder sees varied read boundaries.
    let (split, rest) = data.split_first().map_or((1, data), |(b, r)| (usize::from(*b).max(1), r));
    let mut decoder = ClientDecoder::default();
    'stream: for chunk in rest.chunks(split) {
        decoder.push(chunk);
        loop {
            match decoder.next_msg() {
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(_) => break 'stream,
            }
        }
    }
    let _ = decoder.finish();
    let _ = decode_frame(data);
});
