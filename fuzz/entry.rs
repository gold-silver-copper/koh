//! koh's untrusted inputs, one function each. The fuzz targets (`fuzz_targets/`) and the
//! mutation test (`tests/mutation.rs`) both run these; none may panic, whatever the bytes.
#![allow(dead_code)]

use koh::proto::{
    Attached, ExecClientMsg, ExecServerMsg, JobInfo, KeyProof, LogMsg, Reply, Request, SessionInfo,
    ViewInput, ViewOutput, WaitResult, decode,
};

/// What a peer sends a server: its proof, before the server knows who it is, then a request
/// and the messages of what was asked for (a command's input, a session's keys).
pub fn to_server(data: &[u8]) {
    let _ = decode::<KeyProof>(data, data.len());
    let _ = decode::<Request>(data, data.len());
    let _ = decode::<ExecClientMsg>(data, data.len());
    let _ = decode::<ViewInput>(data, data.len());
}

/// What a server sends a client: the answer to a request, then what was asked for.
pub fn to_client(data: &[u8]) {
    if let Ok(reply) = decode::<Reply>(data, data.len()) {
        let _ = reply.into_result();
    }
    let _ = decode::<Attached>(data, data.len());
    let _ = decode::<ViewOutput>(data, data.len());
    let _ = decode::<ExecServerMsg>(data, data.len());
    let _ = decode::<LogMsg>(data, data.len());
    let _ = decode::<JobInfo>(data, data.len());
    let _ = decode::<Vec<JobInfo>>(data, data.len());
    let _ = decode::<SessionInfo>(data, data.len());
    let _ = decode::<Vec<SessionInfo>>(data, data.len());
    let _ = decode::<WaitResult>(data, data.len());
    let _ = decode::<String>(data, data.len());
}
