//! A pane's folder written by hand as fux's holder writes one, its rounds through the wire, and
//! a mirror: what must be carried right, and what a mirror must not take.

use super::*;
use crate::proto::{MAX_CHUNK, decode, encode};

/// A folder of the test's own, gone when the test is.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("koh-carry-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }

    fn mirror(&self) -> Mirror {
        Mirror::make(&self.0.join("mirror")).unwrap()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Everything in a folder by name, a folder's own too: a file's bytes, where a link leads, what
/// else a name is. With `staged`, the names with a dot first as well (what a round stages).
fn snapshot(dir: &Path, staged: bool) -> BTreeMap<String, Vec<u8>> {
    let mut found = BTreeMap::new();
    let mut folders = vec![(dir.to_path_buf(), String::new())];
    while let Some((folder, prefix)) = folders.pop() {
        for entry in fs::read_dir(&folder).unwrap() {
            let (path, name) = (entry.as_ref().unwrap().path(), entry.unwrap().file_name());
            let name = format!("{prefix}{}", name.to_str().unwrap());
            if name.starts_with('.') && !staged {
                continue;
            }
            let kind = fs::symlink_metadata(&path).unwrap().file_type();
            let what = match () {
                () if kind.is_file() => fs::read(&path).unwrap(),
                () if kind.is_symlink() => {
                    format!("-> {}", fs::read_link(&path).unwrap().display()).into()
                }
                () if kind.is_fifo() => b"a FIFO".to_vec(),
                () => {
                    folders.push((path, format!("{name}/")));
                    b"a folder".to_vec()
                }
            };
            found.insert(name, what);
        }
    }
    found
}

/// A message as the other end has it: within its bound as it is sent, its length counted.
fn sent(message: &ToMirror) -> ToMirror {
    let bytes = encode(message, MAX_CHUNK).unwrap();
    assert!(
        4 + bytes.len() <= MAX_CHUNK,
        "a message of {} bytes",
        bytes.len()
    );
    decode(&bytes, MAX_CHUNK).unwrap()
}

/// Gives a mirror a whole round, which it must take.
fn give(mirror: &mut Mirror, round: &[ToMirror]) {
    let now = Instant::now();
    for message in round {
        let taken = mirror.take(sent(message), now);
        assert!(matches!(taken, Ok(false)), "{message:?}: {taken:?}");
    }
}

fn put(name: &str, bytes: &[u8]) -> ToMirror {
    ToMirror::Put {
        name: name.into(),
        more: false,
        bytes: bytes.to_vec(),
    }
}

/// A piece of a file that more follow.
fn piece(name: &str, bytes: &[u8]) -> ToMirror {
    ToMirror::Put {
        name: name.into(),
        more: true,
        bytes: bytes.to_vec(),
    }
}

fn add(name: &str, at: u64, bytes: &[u8]) -> ToMirror {
    ToMirror::Add {
        name: name.into(),
        at,
        bytes: bytes.to_vec(),
    }
}

fn moved(from: &str, to: &str) -> ToMirror {
    ToMirror::Moved {
        from: from.into(),
        to: to.into(),
    }
}

fn link(name: &str, to: &str) -> ToMirror {
    ToMirror::Link {
        name: name.into(),
        to: to.into(),
    }
}

fn lines_of(name: &str, edits: Vec<Edit>) -> ToMirror {
    ToMirror::Lines {
        name: name.into(),
        edits,
    }
}

fn folder(name: &str) -> ToMirror {
    ToMirror::Folder(name.into())
}

fn fifo(name: &str) -> ToMirror {
    ToMirror::Fifo(name.into())
}

fn remove(name: &str) -> ToMirror {
    ToMirror::Remove(name.into())
}

fn run(from: u32, count: u32) -> Edit {
    Edit::Run { from, count }
}

/// A round of that number with those messages.
fn round_of(number: u64, messages: Vec<ToMirror>) -> Vec<ToMirror> {
    [ToMirror::Round(number)]
        .into_iter()
        .chain(messages)
        .chain([ToMirror::Done])
        .collect()
}

/// The round every mirror of these tests has first.
fn first_round() -> Vec<ToMirror> {
    let screen = put("main/screen", &b"row\n".repeat(60));
    round_of(
        2,
        vec![
            folder("main"),
            put("title", b"a title\n"),
            screen,
            link("shown", "main"),
            fifo("in"),
        ],
    )
}

#[test]
fn a_round_a_server_must_not_send_changes_nothing() {
    let scratch = Scratch::new("hostile");
    let outside = scratch.0.join("escaped").to_str().unwrap().to_string();
    let big = |n: usize| put(&format!("big{n}"), &vec![b'x'; 200 << 10]);
    let grown = |n: usize| lines_of(&format!("big{n}"), vec![run(0, 1); 150]);
    let names = (0..300).map(|n| put(&format!("n{n}"), b"")).collect();
    // What a server sends before the round it must not send, and that round (its number is 8).
    let cases: Vec<(&str, Vec<ToMirror>, Vec<ToMirror>)> = vec![
        (
            "a name that climbs out",
            vec![],
            vec![put("../escaped", b"out\n")],
        ),
        (
            "a name that is a path",
            vec![],
            vec![put(&outside, b"out\n")],
        ),
        (
            "a name of three parts",
            vec![],
            vec![put("main/a/b", b"deep\n")],
        ),
        (
            "a name with a dot first",
            vec![],
            vec![put(".koh/1", b"staged\n")],
        ),
        (
            "a link that leads out",
            vec![],
            vec![link("shown", "../..")],
        ),
        ("a link to a file", vec![], vec![link("shown", "title")]),
        (
            "a link that is then written through",
            vec![],
            vec![link("way", "main"), put("way/screen", b"through\n")],
        ),
        (
            "a link where a folder is",
            vec![],
            vec![link("main", "main")],
        ),
        (
            "a folder where a file is",
            vec![],
            vec![folder("title"), put("title/x", b"x\n")],
        ),
        (
            "the file `generation`",
            vec![],
            vec![put("generation", b"7\n")],
        ),
        (
            "the file `command`",
            vec![],
            vec![put("command", b"sh\0-c\0true\0")],
        ),
        (
            "the file `command` in capitals",
            vec![],
            vec![put("COMMAND", b"sh\0-c\0true\0")],
        ),
        (
            "a move onto `command`",
            vec![],
            vec![moved("title", "command")],
        ),
        ("a FIFO of another name", vec![], vec![fifo("evil")]),
        (
            "bytes added past a file's end",
            vec![],
            vec![add("title", 999, b"far\n")],
        ),
        (
            "bytes added to no file",
            vec![],
            vec![add("nothing", 0, b"new\n")],
        ),
        (
            "lines that would grow to 16 GB",
            vec![big(0)],
            vec![lines_of("big0", vec![run(0, 1); 80_000])],
        ),
        (
            "a run of lines the file has not",
            vec![],
            vec![lines_of("title", vec![run(5, 3)])],
        ),
        (
            "a file in pieces that is never ended",
            vec![],
            vec![piece("title", b"half"), put("main/screen", b"other\n")],
        ),
        (
            "a round inside a round",
            vec![],
            vec![put("title", b"t\n"), ToMirror::Round(10)],
        ),
        (
            "a message over its bound",
            vec![],
            vec![put("title", &vec![b'x'; MAX_CHUNK])],
        ),
        ("more names than a mirror has", vec![], names),
        (
            "lines staged past what a mirror holds",
            (0..5).map(big).collect(),
            (0..5)
                .map(grown)
                .chain((0..5).map(|n| remove(&format!("big{n}"))))
                .collect(),
        ),
        (
            "a link left leading to a file by a later round",
            vec![folder("alt"), link("shown", "alt")],
            vec![remove("alt"), put("alt", b"no folder\n")],
        ),
        // (The first has no `Round` before it; the last one's link ends before its `Done`.)
        ("a message outside a round", vec![], vec![]),
        ("an odd round", vec![], vec![]),
        (
            "a round that never ends",
            vec![],
            vec![put("title", b"changed\n")],
        ),
    ];
    let mut failed = Vec::new();
    for (case, (what, before, hostile)) in cases.into_iter().enumerate() {
        let scratch = Scratch::new(&format!("hostile-{case}"));
        let mut mirror = scratch.mirror();
        give(&mut mirror, &first_round());
        give(&mut mirror, &round_of(4, before));
        let was = snapshot(&scratch.0, true);
        let mut hostile = round_of(8, hostile);
        match what {
            "a message outside a round" => hostile = vec![put("title", b"t\n")],
            "an odd round" => hostile = round_of(9, vec![]),
            "a round that never ends" => _ = hostile.pop(),
            _ => {}
        }
        // (As they are sent, so that one of them can be no message.)
        let refusal = hostile.iter().find_map(|message| {
            let message = decode(&encode(message, usize::MAX).unwrap(), MAX_CHUNK);
            let message = message.map_err(|e| Fault::Refused(e.to_string()));
            message
                .and_then(|message| mirror.take(message, Instant::now()))
                .err()
        });
        let refused = match what {
            "a round that never ends" => refusal.is_none(),
            _ => matches!(refusal, Some(Fault::Refused(_))),
        };
        mirror.discard();
        let staged = was.keys().any(|name| name.starts_with("mirror/.koh/"));
        if !refused || snapshot(&scratch.0, true) != was || staged {
            failed.push(format!("{what}: {refusal:?}"));
        }
    }
    assert!(
        failed.is_empty(),
        "the mirror took, or is not as it was after: {failed:#?}"
    );
    // And one a server may send, though it looks like none: a folder made and removed in one
    // round is a folder when it is removed.
    let mut mirror = scratch.mirror();
    give(&mut mirror, &first_round());
    let mut was = snapshot(&scratch.0, true);
    give(
        &mut mirror,
        &round_of(4, vec![folder("tmp"), put("tmp/x", b"x\n"), remove("tmp")]),
    );
    was.insert("mirror/generation".into(), b"4\n".to_vec());
    assert!(snapshot(&scratch.0, true) == was);
}

/// A second round that has every kind of message, for a mirror that had `first_round`.
fn second_round() -> Vec<ToMirror> {
    let messages = vec![
        moved("title", "title.1"),
        folder("alt"),
        piece("alt/screen", b"an editor's "),
        put("alt/screen", b"screen\n"),
        lines_of(
            "main/screen",
            vec![run(1, 59), Edit::New(b"last\n".to_vec())],
        ),
        add("title.1", 2, b"new "),
        add("title.1", 6, b"title\n"),
        put("title", b"another\n"),
        fifo("ctl"),
        link("shown", "alt"),
        remove("in"),
    ];
    round_of(4, messages)
}

#[test]
fn a_round_cut_at_any_message_leaves_the_round_before() {
    let round = second_round();
    for cut in 0..round.len() {
        let scratch = Scratch::new(&format!("cut-{cut}"));
        let mut mirror = scratch.mirror();
        give(&mut mirror, &first_round());
        let was = snapshot(&scratch.0, true);
        give(&mut mirror, &round[..cut]);
        // (The link is gone.)
        mirror.discard();
        assert!(
            snapshot(&scratch.0, true) == was,
            "cut before message {cut}"
        );
        // The link is back: the round comes whole.
        give(&mut mirror, &round);
        let now = snapshot(&scratch.0.join("mirror"), true);
        let text = |name: &str| String::from_utf8(now[name].clone()).unwrap();
        assert_eq!(
            now.keys().filter(|name| name.starts_with(".koh/")).count(),
            0
        );
        assert_eq!(text("generation"), "4\n");
        assert_eq!(text("title.1"), "a new title\n");
        assert_eq!(text("title"), "another\n");
        assert_eq!(text("alt/screen"), "an editor's screen\n");
        assert_eq!(text("main/screen"), "row\n".repeat(59) + "last\n");
        assert_eq!(text("shown"), "-> alt");
        assert_eq!((text("ctl"), now.get("in")), ("a FIFO".to_string(), None));
        assert!(mirror.fifo("ctl").is_some() && mirror.fifo("in").is_none());
    }
}

#[test]
fn a_round_that_stands_still_or_takes_too_long_is_thrown_away() {
    let scratch = Scratch::new("deadlines");
    let mut mirror = scratch.mirror();
    give(&mut mirror, &first_round());
    let was = snapshot(&scratch.0, true);
    let (began, second) = (Instant::now(), Duration::from_secs(1));
    assert!(mirror.due().is_none(), "no round is open");
    // Thirty seconds between two whole messages of an open round, and no more.
    assert!(matches!(mirror.take(ToMirror::Round(4), began), Ok(false)));
    assert_eq!(mirror.due(), Some(began + STILL));
    assert!(matches!(
        mirror.take(put("title", b"one\n"), began + STILL),
        Ok(false)
    ));
    assert_eq!(mirror.due(), Some(began + 2 * STILL));
    let late = mirror.take(put("main/screen", b"late\n"), began + 2 * STILL + second);
    assert!(matches!(late, Err(Fault::Failed(_))), "{late:?}");
    assert!(mirror.due().is_none() && snapshot(&scratch.0, true) == was);
    // Ten minutes from `Round` to `Done`, though its messages never stop coming.
    assert!(matches!(mirror.take(ToMirror::Round(4), began), Ok(false)));
    for n in 0..30 {
        let more = piece("title", b"more\n");
        assert!(matches!(
            mirror.take(more, began + 20 * n * second),
            Ok(false)
        ));
    }
    assert_eq!(mirror.due(), Some(began + LONG));
    let late = mirror.take(ToMirror::Done, began + LONG + second);
    assert!(matches!(late, Err(Fault::Failed(_))), "{late:?}");
    assert!(mirror.due().is_none() && snapshot(&scratch.0, true) == was);
    // What comes in time is taken.
    give(
        &mut mirror,
        &[
            ToMirror::Round(4),
            put("title", b"in time\n"),
            ToMirror::Done,
        ],
    );
    assert_eq!(
        fs::read(scratch.0.join("mirror/title")).unwrap(),
        b"in time\n"
    );
}
