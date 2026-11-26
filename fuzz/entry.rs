//! koh's untrusted inputs, one function each. The fuzz targets (`fuzz_targets/`) and the
//! mutation test (`tests/mutation.rs`) both run these; none may panic, whatever the bytes.
#![allow(dead_code)]

use koh::proto::{
    Attached, ExecClientMsg, ExecServerMsg, JobInfo, KeyProof, LogMsg, Reply, Request, ViewInput,
    ViewOutput, WaitResult,
};
use serde::de::DeserializeOwned;

/// A message's body as koh reads it, once its length was found within the message's bound.
fn decode<T: DeserializeOwned>(data: &[u8]) -> Option<T> {
    postcard::from_bytes(data).ok()
}

/// What a peer sends a server: its proof, before the server knows who it is, then a request
/// and the messages of what was asked for (a command's input, a session's keys).
pub fn to_server(data: &[u8]) {
    let _ = decode::<KeyProof>(data);
    let _ = decode::<Request>(data);
    let _ = decode::<ExecClientMsg>(data);
    let _ = decode::<ViewInput>(data);
}

/// What a server sends a client: the answer to a request, then what was asked for.
pub fn to_client(data: &[u8]) {
    if let Some(reply) = decode::<Reply>(data) {
        let _ = reply.into_result();
    }
    let _ = decode::<Attached>(data);
    let _ = decode::<ViewOutput>(data);
    let _ = decode::<ExecServerMsg>(data);
    let _ = decode::<LogMsg>(data);
    let _ = decode::<JobInfo>(data);
    let _ = decode::<Vec<JobInfo>>(data);
    let _ = decode::<WaitResult>(data);
    let _ = decode::<String>(data);
}
