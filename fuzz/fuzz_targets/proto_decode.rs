#![no_main]
//! Fuzz both directions of the koh/3 wire decode: arbitrary bytes as the client's message stream
//! (the server's parser) and as a server stream (the client's parser: bounded inflate, against a
//! dictionary for a frame, plus postcard). Both must only return errors on bad input, never
//! panic, and never allocate past their caps.

use koh::proto::{decode_frame_body, decode_server, ClientDecoder, FrameNum};
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
    let _ = decode_server(data);
    // A frame's body against a dictionary: the first half of the bytes as the dictionary, the
    // rest as the body, as a server could send against any base.
    let (dictionary, body) = rest.split_at(rest.len() / 2);
    let _ = decode_frame_body(FrameNum(1), body, dictionary);
});
