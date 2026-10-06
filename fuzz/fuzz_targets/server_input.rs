#![no_main]
//! Fuzz the server's encoding of what a client sends: the first part of the input as the
//! program's output (setting any keyboard, mouse, focus and paste modes), the rest as the client's
//! message stream, every `Keys` message's events encoded for the program by
//! `ServerTerminal::encode_input`. A hostile client controls the events; the server must never
//! panic, and a framed paste must hold no end marker but its own.

use koh::proto::{ClientDecoder, ClientMsg};
use koh::terminal::ServerTerminal;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&cut, rest)) = data.split_first() else {
        return;
    };
    let (output, stream) = rest.split_at(usize::from(cut).min(rest.len()));
    let Ok(mut t) = ServerTerminal::new(24, 80, 0) else {
        return;
    };
    t.process(output);
    let _ = t.take_host_replies();
    let mut decoder = ClientDecoder::default();
    decoder.push(stream);
    let mut out = Vec::new();
    while let Ok(Some(msg)) = decoder.next_msg() {
        match msg {
            ClientMsg::Keys { events, .. } => t.encode_input(&events, &mut out),
            ClientMsg::Colours(colours) => out.extend(t.set_colours(&colours)),
            _ => {}
        }
    }
    // No key, mouse or focus encoding is `ESC [ 201 ~`, and pieces lose their markers: so every
    // end marker closes a paste the server opened, and no paste holds one.
    let mut open = false;
    let mut at = 0usize;
    while let Some(i) = out
        .get(at..)
        .and_then(|o| o.windows(6).position(|w| w == b"\x1b[200~" || w == b"\x1b[201~"))
    {
        let start = at + i;
        if out.get(start + 4) == Some(&b'0') {
            assert!(!open, "a paste opened inside another");
            open = true;
        } else {
            assert!(open, "an end marker with no paste open: {out:?}");
            open = false;
        }
        at = start + 6;
    }
});
