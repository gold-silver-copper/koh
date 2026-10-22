#![no_main]
//! Fuzz what a peer sends outside a session's streams: the key proof any client opens with (reached
//! by anyone who completes a handshake), the opening request a client makes (the server's parser,
//! reached by any allowed client before anything is attached), the answers a
//! server sends whole, a job's log, and a copy's items and replies, which either end may send.
//! Each must only return errors on bad input, never panic, and never allocate past its bound.

use koh::request::{
    decode, Answer, Attached, ExitStatus, JobList, KeyProof, LogMsg, Request, SessionList, Started,
    Waited,
};
use koh::sync::{Item, Reply};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = decode::<KeyProof>(data);
    let _ = decode::<Request>(data);
    let _ = decode::<Attached>(data);
    let _ = decode::<Answer<SessionList>>(data);
    let _ = decode::<Answer<JobList>>(data);
    let _ = decode::<Answer<Started>>(data);
    let _ = decode::<Answer<Waited>>(data);
    let _ = decode::<Answer<String>>(data);
    let _ = decode::<ExitStatus>(data);
    let _ = decode::<LogMsg>(data);
    let _ = decode::<Item>(data);
    let _ = decode::<Reply>(data);
});
