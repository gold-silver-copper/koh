//! koh's untrusted inputs, one function each. The fuzz targets (`fuzz_targets/`) and the
//! mutation test (`tests/mutation.rs`) both run these; none may panic, whatever the bytes.
#![allow(dead_code)]

use koh::KohError;
use koh::proto::{
    ClientEvent, ExecClientMsg, ExecServerMsg, JobInfo, KeyProof, LogMsg, Reply, Request,
    ScreenFrame, ServerEvent, SessionInfo, SyncMsg, WaitResult,
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
    let _ = decode::<ClientEvent>(data);
    let _ = decode::<ExecClientMsg>(data);
    sync_msg(data);
}

/// What a server sends a client: the answer to a request, then what was asked for.
pub fn to_client(data: &[u8]) {
    if let Some(reply) = decode::<Reply>(data) {
        let _ = reply.into_result();
    }
    let _ = decode::<ServerEvent>(data);
    let _ = decode::<ExecServerMsg>(data);
    let _ = decode::<LogMsg>(data);
    let _ = decode::<JobInfo>(data);
    let _ = decode::<Vec<JobInfo>>(data);
    let _ = decode::<Vec<SessionInfo>>(data);
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

/// A session's screen and what follows it, as a client mirrors them: a frame is held to the
/// bounds of a screen, and no update takes it out of them.
pub fn frames(data: &[u8]) {
    let Some((mut frame, events)) = decode::<(ScreenFrame, Vec<ServerEvent>)>(data) else {
        return;
    };
    frame.clamp_bounds();
    in_bounds(&frame);
    for event in events {
        match event {
            ServerEvent::Full(mut next) => {
                next.clamp_bounds();
                frame = next;
            }
            ServerEvent::Delta(delta) => {
                let changed = frame.apply_delta(delta);
                assert!(changed.iter().all(|row| *row < frame.rows));
            }
            ServerEvent::Picture(_) => {}
        }
        in_bounds(&frame);
    }
}

fn in_bounds(frame: &ScreenFrame) {
    assert!(frame.cols <= fux_vt::SIZE_MAX && frame.rows <= fux_vt::SIZE_MAX);
    assert!(frame.cursor_row < frame.rows.max(1) && frame.cursor_col < frame.cols.max(1));
    let ids = frame.referenced_picture_ids();
    assert!(ids.is_sorted_by(|a, b| a < b));
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
        assert!((1..=128).contains(&names.len()));
        let plain = |name: &&str| !matches!(*name, "" | "." | "..") && !name.contains(['/', '\0']);
        assert!(names.iter().all(plain));
        assert_eq!(names.join("/"), path);
    }
    let patterns: Vec<String> = lines.map(String::from).collect();
    let _ = koh::sync::matches_exclude(path, &patterns);
}
