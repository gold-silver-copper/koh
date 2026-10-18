#![no_main]
//! Fuzz the client's input path: arbitrary bytes as the user's terminal sends them, read in
//! pieces, through the client's input machine and its Escape deadline, with the terminal's answers
//! to the start-up questions expected, as at the start of every run. The terminal is the user's,
//! but its bytes are untrusted input to a decoder all the same (a paste, a program writing to the
//! client's tty). It must never panic, every message it makes must encode and decode back to
//! itself, and the answers must not be typed: it never sends more keys and pasted text than
//! bytes it read.

use std::time::Instant;

use koh::client::input::Keys;
use koh::events::{InputEvent, MAX_EVENTS};
use koh::proto::{encode_client, ClientDecoder, ClientMsg, InputSeq};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (split, rest) = data
        .split_first()
        .map_or((1, data), |(b, r)| (usize::from(*b).max(1), r));
    let now = Instant::now();
    let mut keys = Keys::new(now, true);
    let mut wire = ClientDecoder::default();
    let mut typed = 0usize;
    for chunk in rest.chunks(split) {
        let mut reads = vec![keys.bytes(now, chunk)];
        if let Some(deadline) = keys.deadline() {
            reads.push(keys.timeout(deadline));
        }
        let _ = keys.take_questions();
        for read in reads {
            for events in read.events.chunks(MAX_EVENTS) {
                let msg = ClientMsg::Keys {
                    seq: InputSeq(1),
                    events: events.to_vec(),
                };
                let bytes = encode_client(&msg).expect("the client's messages encode");
                wire.push(&bytes);
                let back = wire.next_msg().expect("and decode").expect("whole");
                assert_eq!(back, msg);
                typed += events
                    .iter()
                    .map(|event| match event {
                        InputEvent::Paste(text) => text.len(),
                        _ => 1,
                    })
                    .sum::<usize>();
            }
        }
    }
    assert!(typed <= rest.len(), "{typed} typed of {} read", rest.len());
});
