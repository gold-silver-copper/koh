//! koh's untrusted inputs, one function each. The fuzz targets (`fuzz_targets/`) and the
//! mutation test (`tests/mutation.rs`) both run these; none may panic, whatever the bytes.
#![allow(dead_code)]

use koh::KohError;
use koh::proto::{
    Attached, ExecClientMsg, ExecServerMsg, JobInfo, KeyProof, LogMsg, Reply, Request, SyncMsg,
    ViewInput, ViewOutput, WaitResult,
};
use serde::de::DeserializeOwned;

/// A message's body as koh reads it, once its length was found within the message's bound.
fn decode<T: DeserializeOwned>(data: &[u8]) -> Option<T> {
    postcard::from_bytes(data).ok()
}

/// What a peer sends a server: its proof, before the server knows who it is, then a request
/// and the messages of what was asked for (a copy, a command's input, a session's keys).
pub fn to_server(data: &[u8]) {
    let _ = decode::<KeyProof>(data);
    let _ = decode::<Request>(data);
    let _ = decode::<ExecClientMsg>(data);
    let _ = decode::<ViewInput>(data);
    sync_msg(data);
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
    sync_msg(data);
}

/// A copy's messages go both ways; one that says why the other end stopped becomes an error.
fn sync_msg(data: &[u8]) {
    if let Some(SyncMsg::Failed(why)) = decode::<SyncMsg>(data) {
        let _ = KohError::from(why);
    }
}

/// The first line as a path a copy's peer names, the rest as the patterns that leave entries
/// out: a path that is taken is plain names beneath the tree, and nothing else.
pub fn paths(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let mut lines = text.split('\n');
    let path = lines.next().unwrap_or_default();
    if let Ok(names) = koh::sync::wire_names(path) {
        assert!((1..=129).contains(&names.len()));
        let plain = |name: &&str| !matches!(*name, "" | "." | "..") && !name.contains(['/', '\0']);
        assert!(names.iter().all(plain));
        assert_eq!(names.join("/"), path);
    }
    let patterns: Vec<String> = lines.map(String::from).collect();
    let _ = koh::sync::matches_exclude(path, &patterns);
}
