//! koh's untrusted inputs, one function each. The fuzz targets (`fuzz_targets/`) and the
//! mutation test (`tests/mutation.rs`) both run these; none may panic, whatever the bytes.
#![allow(dead_code)]

use koh::proto::{
    Attached, ExecServerMsg, JobInfo, KeyProof, LogMsg, MAX_CHUNK, MAX_CTRL, MAX_FRAME, MAX_PROOF,
    Reply, Request, SessionInfo, VIEW_FRAME, ViewInput, ViewOutput, WaitResult, decode,
};

/// What a peer sends a server: its proof, before the server knows who it is, then a request
/// and the messages of what was asked for (a session's keys).
pub fn to_server(data: &[u8]) {
    let _ = decode::<KeyProof>(data, MAX_PROOF);
    let _ = decode::<Request>(data, MAX_CTRL);
    let _ = decode::<ViewInput>(data, VIEW_FRAME);
}

/// What a server sends a client: the answer to a request, then what was asked for.
pub fn to_client(data: &[u8]) {
    if let Ok(reply) = decode::<Reply>(data, MAX_CTRL) {
        let _ = reply.into_result();
    }
    let _ = decode::<Attached>(data, MAX_CTRL);
    let _ = decode::<ViewOutput>(data, VIEW_FRAME);
    let _ = decode::<ExecServerMsg>(data, MAX_CHUNK);
    let _ = decode::<LogMsg>(data, MAX_CHUNK);
    let _ = decode::<JobInfo>(data, MAX_CTRL);
    let _ = decode::<Vec<JobInfo>>(data, MAX_CTRL);
    let _ = decode::<SessionInfo>(data, usize::MAX);
    let _ = decode::<Vec<SessionInfo>>(data, usize::MAX);
    let _ = decode::<WaitResult>(data, MAX_FRAME);
    let _ = decode::<Vec<u8>>(data, MAX_CHUNK);
}
