#![no_main]
//! Fuzz the client's input path: arbitrary bytes as the user's terminal sends them, read in
//! pieces, through `ClientSession::on_input` and its Escape deadline, with the terminal's answers
//! to the start-up questions expected, as at the start of every run. The terminal is the user's,
//! but its bytes are untrusted input to a decoder all the same (a paste, a program writing to the
//! client's tty). It must never panic, every message the session makes must encode, decode
//! back to itself, and be within the wire's bounds, and the answers must not be typed: it never
//! sends more keys and pasted text than bytes it read.

use std::time::Instant;

use koh::client::ClientSession;
use koh::events::InputEvent;
use koh::proto::{encode_client, ClientDecoder, ClientMsg};
use koh::terminal::Size;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (split, rest) = data
        .split_first()
        .map_or((1, data), |(b, r)| (usize::from(*b).max(1), r));
    let mut session = ClientSession::new(Size::new(24, 80));
    let now = Instant::now();
    session.ask_terminal(now, true);
    let mut wire = ClientDecoder::default();
    let mut typed = 0usize;
    for chunk in rest.chunks(split) {
        session.on_input(now, chunk);
        if let Some(deadline) = session.deadline() {
            session.on_timeout(deadline);
        }
        let _ = (session.take_questions(), session.take_found());
        while let Some(msg) = session.pop_outgoing() {
            let bytes = encode_client(&msg).expect("the session's messages encode");
            wire.push(&bytes);
            let back = wire.next_msg().expect("and decode").expect("whole");
            assert_eq!(back, msg);
            if let ClientMsg::Keys { events, .. } = msg {
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
