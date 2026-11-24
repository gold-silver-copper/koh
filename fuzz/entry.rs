//! koh's untrusted inputs, one function each. The fuzz targets (`fuzz_targets/`) and the
//! mutation test (`tests/mutation.rs`) both run these; none may panic, whatever the bytes.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use koh::KohError;
use koh::carry::{Fault, Mirror, Reader};
use koh::proto::{
    ClientEvent, ExecClientMsg, ExecServerMsg, FromMirror, JobInfo, KeyProof, LogMsg, MAX_CHUNK,
    Reply, Request, ScreenFrame, ServerEvent, SessionInfo, SyncMsg, ToMirror, WaitResult,
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
        assert!((1..=129).contains(&names.len()));
        let plain = |name: &&str| !matches!(*name, "" | "." | "..") && !name.contains(['/', '\0']);
        assert!(names.iter().all(plain));
        assert_eq!(names.join("/"), path);
    }
    let patterns: Vec<String> = lines.map(String::from).collect();
    let _ = koh::sync::matches_exclude(path, &patterns);
}

/// Any bytes as a message of a carried pane, either way, as koh reads one: all of it or none.
/// A list of what a mirror has is checked before any folder is looked at: here there is none.
pub fn carry_decode(data: &[u8]) {
    let _ = koh::proto::decode::<ToMirror>(data, MAX_CHUNK);
    if let Ok(FromMirror::Has(list)) = koh::proto::decode(data, MAX_CHUNK) {
        let nowhere = std::env::temp_dir().join("koh-fuzz-no-pane");
        assert!(!matches!(Reader::new(&nowhere).has(&list, false), Ok(true)));
    }
}

/// What a folder holds, by name: a file's bytes, where a link leads, what else a name is.
fn held(dir: &Path, prefix: &str, found: &mut BTreeMap<String, Vec<u8>>) {
    for entry in fs::read_dir(dir).into_iter().flatten().flatten() {
        let (path, name) = (
            entry.path(),
            entry.file_name().to_string_lossy().into_owned(),
        );
        let kind = entry.file_type().unwrap();
        let what = match () {
            () if kind.is_file() => [b"file ", fs::read(&path).unwrap().as_slice()].concat(),
            () if kind.is_symlink() => {
                format!("-> {}", fs::read_link(&path).unwrap().display()).into()
            }
            () if kind.is_dir() => b"folder".to_vec(),
            () => b"other".to_vec(),
        };
        if kind.is_dir() {
            held(&path, &format!("{prefix}{name}/"), found);
        }
        found.insert(format!("{prefix}{name}"), what);
    }
}

/// Any messages a server sends, one after the other, into a mirror made for them. After each
/// that is not taken, and when no more come, the mirror is what the last whole round left; and
/// what a whole round leaves is a mirror: its number in `generation`, every link to a folder of
/// its own, no `command` and no `status`, no name in two spellings, nothing staged. Nothing is
/// ever beside it.
pub fn carry_sequence(data: &[u8]) {
    static RUNS: AtomicU64 = AtomicU64::new(0);
    let Some(messages) = decode::<Vec<ToMirror>>(data) else {
        return;
    };
    let run = RUNS.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!("koh-fuzz-{}-{run}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let mut mirror = Mirror::make(&root.join("mirror")).unwrap();
    let look = || {
        let mut found = BTreeMap::new();
        held(&root, "", &mut found);
        found
    };
    let (mut whole, mut number, now) = (look(), 0, Instant::now());
    for message in messages {
        let done = message == ToMirror::Done;
        if let ToMirror::Round(n) = message {
            number = n;
        }
        match mirror.take(message, now) {
            Ok(_) if done => {
                whole = look();
                let is = |name: &str, what: &str| {
                    whole.get(name).is_some_and(|is| is == what.as_bytes())
                };
                assert!(
                    is("mirror/generation", &format!("file {number}\n"))
                        && is("mirror/.koh", "folder")
                );
                for (full, what) in &whole {
                    let name = full.strip_prefix("mirror/").unwrap_or(full);
                    let led = what
                        .strip_prefix(b"-> ")
                        .map(|to| format!("mirror/{}", String::from_utf8_lossy(to)));
                    assert!(
                        led.is_none_or(|to| !name.contains('/') && is(&to, "folder")),
                        "{name}"
                    );
                    let never = |never: &str| name.eq_ignore_ascii_case(never);
                    assert!(
                        !never("command") && !never("status") && !name.starts_with(".koh/"),
                        "{name}"
                    );
                    let other = |other: &&String| other.eq_ignore_ascii_case(full);
                    assert_eq!(
                        whole.keys().filter(other).count(),
                        1,
                        "{name} in two spellings"
                    );
                }
            }
            Ok(_) => {}
            Err(Fault::Refused(_)) => {
                assert!(look() == whole, "a refused message changed the mirror")
            }
            // (A round that could not be written leaves the mirror between two: the next list says how.)
            Err(Fault::Failed(_)) => whole.clear(),
        }
        if whole.is_empty() {
            break;
        }
    }
    mirror.discard();
    let left = look();
    assert!(
        whole.is_empty() || left == whole,
        "the mirror is not what the last whole round left"
    );
    assert!(left.keys().all(|name| name.starts_with("mirror")));
    let _ = fs::remove_dir_all(&root);
}
