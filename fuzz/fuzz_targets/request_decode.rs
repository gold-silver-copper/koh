#![no_main]
//! Fuzz what a peer sends outside a session's streams: the opening request a client makes (the
//! server's parser, reached by any allowed client before anything is attached), the replies a
//! server sends whole, and a copy's items, which either end may send. Each must only return
//! errors on bad input, never panic, and never allocate past its bound.

use koh::copy::Item;
use koh::request::{decode, Attached, ExitStatus, Request, SessionList};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = decode::<Request>(data);
    let _ = decode::<Attached>(data);
    let _ = decode::<SessionList>(data);
    let _ = decode::<ExitStatus>(data);
    let _ = decode::<Item>(data);
    let _ = decode::<Result<(), koh::copy::Failure>>(data);
});
