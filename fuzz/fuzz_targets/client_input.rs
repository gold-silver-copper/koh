#![no_main]
//! Fuzz the client's input path: arbitrary bytes as the user's terminal sends them, read in
//! pieces, through `ClientSession::on_input` and its Escape deadline. The terminal is the user's,
//! but its bytes are untrusted input to a decoder all the same (a paste, a program writing to the
//! client's tty). It must never panic; every message the session makes must encode, decode back
//! to itself, and be within the wire's bounds; and no paste piece may hold an end marker.

use std::time::Instant;

use koh::client::ClientSession;
use koh::events::InputEvent;
use koh::predict::DisplayPreference;
use koh::proto::{encode_client, ClientDecoder, ClientMsg};
use koh::terminal::Size;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (split, rest) = data.split_first().map_or((1, data), |(b, r)| (usize::from(*b).max(1), r));
    let mut session = ClientSession::new(DisplayPreference::Always, Size::new(24, 80));
    let now = Instant::now();
    let mut wire = ClientDecoder::default();
    for chunk in rest.chunks(split) {
        session.on_input(now, chunk);
        if let Some(deadline) = session.deadline() {
            session.on_timeout(deadline);
        }
        let _ = session.take_questions();
        while let Some(msg) = session.pop_outgoing() {
            if let ClientMsg::Keys { events, .. } = &msg {
                for event in events {
                    if let InputEvent::Paste { text, .. } = event {
                        assert!(!text.contains("\x1b[201~"), "{text:?}");
                        assert!(!text.contains("\u{9b}201~"), "{text:?}");
                    }
                }
            }
            let bytes = encode_client(&msg).expect("the session's messages encode");
            wire.push(&bytes);
            let back = wire.next_msg().expect("and decode").expect("whole");
            assert_eq!(back, msg);
        }
    }
});
