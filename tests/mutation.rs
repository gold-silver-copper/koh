//! The fuzz targets' entry points (`fuzz/entry.rs`) under a mutation run that every `cargo test`
//! repeats exactly: a fixed seed, a fixed number of rounds, a few seconds at most. It stands in
//! for coverage-guided fuzzing where that cannot run, and keeps the entry points compiling.

#[path = "../fuzz/entry.rs"]
mod entry;

use koh::proto::{
    ClientEvent, Edit, ExecClientMsg, ExecServerMsg, Failure, FrameDelta, FromMirror, Had, JobInfo,
    KeyProof, Kind, LogMsg, PictureBlob, PictureKind, Reply, Request, RowPatch, ScreenFrame,
    ServerEvent, SessionInfo, SyncEntry, SyncMsg, SyncSummary, ToMirror, WaitResult,
};

/// xorshift64*: the same numbers on every run.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

fn bytes<T: serde::Serialize>(value: &T) -> Vec<u8> {
    postcard::to_allocvec(value).unwrap()
}

fn frame() -> ScreenFrame {
    ScreenFrame {
        session_id: 3,
        generation: 8,
        cols: 20,
        rows: 4,
        screen: "one\ntwo\n\nfour\n".into(),
        styled: "one\n\x1b[31mtwo\x1b[m\n\nfour\n".into(),
        lines: "0\n".into(),
        links: "1 https://example.org\n".into(),
        pictures: "pic-2.png 0 0 4 2 10 20\npic-1.sixel -1 3 4 2 10 20\n".into(),
        cursor_row: 3,
        cursor_col: 4,
        cursor_shown: true,
        cursor_colour: Some([1, 2, 3]),
        modes: "paste keys=3".into(),
        title: "sh".into(),
        marks: "prompt 0\nend 7 2\n".into(),
        state: "running".into(),
        clipboard: Some(b"copied".to_vec()),
        notice: Some("done".into()),
        ..ScreenFrame::default()
    }
}

fn delta() -> FrameDelta {
    let mut next = frame();
    next.screen = "one\nTWO\n\nfour\n".into();
    next.pictures.clear();
    next.title = "vi".into();
    let mut delta = next.diff(&frame()).unwrap();
    delta.changed_rows.push(RowPatch {
        row: 3,
        screen: "last".into(),
        styled: "last".into(),
    });
    delta
}

/// One valid encoding of every message a peer sends, and paths as a copy's peer names them.
fn seeds() -> Vec<Vec<u8>> {
    let text = |s: &str| s.to_string();
    let entry = SyncEntry {
        path: text("dir/file.txt"),
        size: 5,
        mtime_secs: 1_700_000_000,
        mode: 0o644,
        hash: [7; 32],
        is_dir: false,
    };
    let job = JobInfo {
        name: text("build"),
        pid: 4242,
        state: text("exited 0"),
        exit: Some(0),
        age_secs: 9,
        command: text("make -j4"),
    };
    let session = SessionInfo {
        id: 1,
        attached: true,
        state: text("running"),
        cols: 80,
        rows: 24,
        title: text("sh"),
        running_command: false,
        last_exit: Some(1),
        age_secs: 3,
        pane_dir: text("/run/koh/sessions/s1"),
    };
    let picture = PictureBlob {
        id: 2,
        kind: PictureKind::Png,
        bytes: vec![0x89, b'P', b'N', b'G'],
    };
    let events = vec![
        ServerEvent::Delta(delta()),
        ServerEvent::Picture(picture.clone()),
        ServerEvent::Full(frame()),
        ServerEvent::Delta(delta()),
    ];
    vec![
        bytes(&KeyProof {
            key: [9; 32],
            signature: vec![1; 64],
        }),
        bytes(&Request::Exec {
            argv: vec![text("uname"), text("-a")],
            cwd: Some(text("~/proj")),
            shell: false,
        }),
        bytes(&Request::Run {
            name: Some(text("build")),
            argv: vec![text("make")],
            cwd: None,
            shell: true,
        }),
        bytes(&Request::Jobs { name: None }),
        bytes(&Request::Logs {
            name: text("build"),
            tail: Some(200),
            all: false,
            follow: true,
        }),
        bytes(&Request::Kill {
            name: text("build"),
            signal: 15,
        }),
        bytes(&Request::WaitJob {
            name: text("build"),
            text: Some(text("READY")),
            tail: 50,
            timeout_secs: Some(5),
        }),
        bytes(&Request::CpPush {
            dst: text("proj"),
            excludes: vec![text("target"), text("*.o")],
            delete: true,
            preserve_mtime: true,
            dry_run: false,
        }),
        bytes(&Request::CpPull {
            src: text("proj/src"),
            excludes: vec![text("**/tmp")],
            delete: false,
            preserve_mtime: false,
            dry_run: true,
            preserve_root: true,
        }),
        bytes(&Request::Sessions),
        bytes(&Request::Output {
            session: 1,
            last: true,
        }),
        bytes(&Request::WaitSession {
            session: 1,
            timeout_secs: None,
        }),
        bytes(&Request::Attach {
            session: Some(1),
            new: false,
            cols: 80,
            rows: 24,
            cell_w: 10,
            cell_h: 20,
            argv: vec![text("vi")],
            cwd: Some(text("/tmp")),
        }),
        bytes(&ClientEvent::Input(b"ls\r".to_vec())),
        bytes(&ClientEvent::Resize {
            cols: 100,
            rows: 30,
            cell_w: 9,
            cell_h: 18,
        }),
        bytes(&ClientEvent::Colours(text("foreground #aabbcc\n"))),
        bytes(&ClientEvent::Keyboard(3)),
        bytes(&ClientEvent::Detach),
        bytes(&ExecClientMsg::Stdin(b"in".to_vec())),
        bytes(&ExecClientMsg::Eof),
        bytes(&SyncMsg::Manifest(vec![entry.clone(), entry])),
        bytes(&SyncMsg::Need(vec![text("dir/file.txt")])),
        bytes(&SyncMsg::FileStart {
            path: text("dir/file.txt"),
            size: 5,
            mtime_secs: -1,
            mode: 0o755,
        }),
        bytes(&SyncMsg::FileChunk(b"hello".to_vec())),
        bytes(&SyncMsg::FileEnd),
        bytes(&SyncMsg::Summary(SyncSummary {
            added: vec![text("a")],
            updated: vec![text("b")],
            deleted: vec![text("c")],
            unchanged: 4,
            bytes_transferred: 5,
            dry_run: false,
        })),
        bytes(&SyncMsg::Failed(Failure {
            code: 4,
            kind: text("refused"),
            message: text("dir: \"link\" is a symlink"),
        })),
        bytes(&Reply::Ok),
        bytes(&Reply::Err {
            code: 75,
            kind: text("busy"),
            message: text("server busy"),
        }),
        bytes(&ExecServerMsg::Stdout(b"out".to_vec())),
        bytes(&ExecServerMsg::Stderr(b"err".to_vec())),
        bytes(&ExecServerMsg::Exit(-1)),
        bytes(&LogMsg::Data(b"log".to_vec())),
        bytes(&LogMsg::Done {
            state: text("killed 9"),
            exit: Some(137),
            age_secs: 2,
        }),
        bytes(&vec![job.clone(), job]),
        bytes(&vec![session]),
        bytes(&WaitResult {
            timed_out: true,
            exit: 124,
            tail: text("tail"),
            detail: text("timed out"),
        }),
        bytes(&ServerEvent::Full(frame())),
        bytes(&ServerEvent::Delta(delta())),
        bytes(&ServerEvent::Picture(picture)),
        bytes(&(frame(), events)),
        bytes(&ToMirror::Round(4)),
        bytes(&ToMirror::Lines {
            name: text("main/screen"),
            edits: vec![
                Edit::Run { from: 1, count: 23 },
                Edit::New(b"$ \n".to_vec()),
            ],
        }),
        bytes(&ToMirror::Add {
            name: text("history"),
            at: 4096,
            bytes: b"a line\n".to_vec(),
        }),
        bytes(&FromMirror::Has(vec![
            Had {
                name: text("main/screen"),
                kind: Kind::File,
                len: 48,
                hash: [7; 32],
            },
            Had {
                name: text("shown"),
                kind: Kind::Link,
                len: 0,
                hash: [0; 32],
            },
        ])),
        bytes(&FromMirror::Write {
            name: text("in"),
            bytes: b"ls\r".to_vec(),
        }),
        bytes(&FromMirror::Told {
            name: text("keyboard"),
            bytes: b"5\n".to_vec(),
        }),
        b"dir/sub/file.txt\ntarget\n*.o\nsub/**/x?".to_vec(),
        b"../etc/passwd\n**\n".to_vec(),
        b"a//b/./c\0d\n*a*b*c*d*\n?".to_vec(),
    ]
}

const EDGES: [u8; 8] = [0x00, 0x01, 0x7f, 0x80, 0xff, b'/', b'.', b'\n'];

/// One change to `data`: a bit, a byte, a length, a cut, or a piece of another message.
fn mutate(rng: &mut Rng, data: &mut Vec<u8>, seeds: &[Vec<u8>]) {
    let at = rng.below(data.len());
    match rng.below(8) {
        0 => {
            if let Some(byte) = data.get_mut(at) {
                *byte ^= 1 << rng.below(8);
            }
        }
        1 => {
            if let Some(byte) = data.get_mut(at) {
                *byte = EDGES[rng.below(EDGES.len())];
            }
        }
        2 => data.truncate(at),
        3 => data.insert(at.min(data.len()), rng.next() as u8),
        // A length (or any number) as large as the wire can say it.
        4 => {
            let huge = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01];
            let n = 1 + rng.below(huge.len());
            data.splice(at..at.min(data.len()), huge[..n].iter().copied());
        }
        5 => {
            let end = (at + 1 + rng.below(16)).min(data.len());
            let piece = data[at..end].to_vec();
            let to = rng.below(data.len() + 1);
            data.splice(to..to, piece);
        }
        6 => {
            let other = &seeds[rng.below(seeds.len())];
            let from = rng.below(other.len());
            data.truncate(at);
            data.extend_from_slice(&other[from..]);
        }
        _ => {
            let end = (at + 1 + rng.below(8)).min(data.len());
            data.drain(at..end);
        }
    }
}

/// A size, row or column as a hostile server would say it: at and past every bound.
fn number(rng: &mut Rng) -> usize {
    const EDGES: [usize; 9] = [0, 1, 3, 4, 5, 499, 500, 501, usize::MAX];
    EDGES[rng.below(EDGES.len())]
}

/// A few short lines, some of them a picture's.
fn lines(rng: &mut Rng) -> String {
    let mut text = String::new();
    for _ in 0..rng.below(7) {
        match rng.below(4) {
            0 => text.push_str(&format!("pic-{}.png 0 0 1 1 10 20", rng.below(5))),
            1 => text.push_str("\x1b[1mbold\x1b[m"),
            2 => {}
            _ => text.push_str("row"),
        }
        text.push('\n');
    }
    if rng.below(3) == 0 {
        text.pop();
    }
    text
}

/// A screen and updates to it that decode, built of such numbers and lines: what bytes changed
/// at random seldom are.
fn screens(rng: &mut Rng) -> Vec<u8> {
    let mut first = ScreenFrame {
        cols: number(rng),
        rows: number(rng),
        cursor_row: number(rng),
        cursor_col: number(rng),
        screen: lines(rng),
        styled: lines(rng),
        pictures: lines(rng),
        ..frame()
    };
    let mut events = Vec::new();
    for _ in 0..rng.below(5) {
        if rng.below(4) == 0 {
            first.rows = number(rng);
            events.push(ServerEvent::Full(first.clone()));
            continue;
        }
        let mut update = delta();
        update.changed_rows = (0..rng.below(5))
            .map(|_| RowPatch {
                row: number(rng),
                screen: lines(rng),
                styled: lines(rng),
            })
            .collect();
        (update.cursor_row, update.cursor_col) = (number(rng), number(rng));
        update.pictures = Some(lines(rng));
        events.push(ServerEvent::Delta(update));
    }
    bytes(&(first, events))
}

#[test]
fn no_mutated_message_panics_a_decoder_or_takes_a_frame_out_of_bounds() {
    let seeds = seeds();
    let run = |data: &[u8]| {
        entry::to_server(data);
        entry::to_client(data);
        entry::frames(data);
        entry::paths(data);
        entry::carry_decode(data);
    };
    for seed in &seeds {
        run(seed);
    }
    let mut rng = Rng(0x6b6f_6820_6675_7a7a);
    for _ in 0..ROUNDS {
        for seed in &seeds {
            let mut data = seed.clone();
            for _ in 0..1 + rng.below(4) {
                mutate(&mut rng, &mut data, &seeds);
            }
            run(&data);
        }
        for _ in 0..4 {
            entry::frames(&screens(&mut rng));
        }
    }
}

/// A server's messages for a mirror, built of a few names, fair ones and those a hostile server
/// would try, and of every kind of message: rounds that are whole and rounds that are not.
fn rounds(rng: &mut Rng) -> Vec<u8> {
    const NAMES: [&str; 16] = [
        "main",
        "alt",
        "shown",
        "title",
        "history",
        "main/screen",
        "alt/screen",
        "in",
        "ctl",
        "x",
        "MAIN",
        "../x",
        ".koh/1",
        "generation",
        "COMMAND",
        "a/b/c",
    ];
    // (The first ten are names a mirror may have: most messages are of those.)
    let name = |rng: &mut Rng| {
        let among = if rng.below(6) == 0 { 16 } else { 10 };
        NAMES[rng.below(among)].to_string()
    };
    let data = |rng: &mut Rng| b"line\n".repeat(rng.below(40));
    // (A fair round first, so that there is a mirror for the others to change or to spoil.)
    let mut messages = vec![
        ToMirror::Round(2),
        ToMirror::Folder("main".into()),
        ToMirror::Put {
            name: "main/screen".into(),
            more: false,
            bytes: data(rng),
        },
        ToMirror::Put {
            name: "title".into(),
            more: false,
            bytes: data(rng),
        },
        ToMirror::Fifo("in".into()),
        ToMirror::Done,
    ];
    for round in 2..=2 + rng.below(6) {
        messages.push(ToMirror::Round(
            2 * round as u64 + u64::from(rng.below(30) == 0),
        ));
        for _ in 0..rng.below(4) {
            messages.push(match rng.below(12) {
                0 => ToMirror::Folder(name(rng)),
                1 => ToMirror::Fifo(name(rng)),
                2 => ToMirror::Link {
                    name: name(rng),
                    to: name(rng),
                },
                3 | 4 => ToMirror::Put {
                    name: name(rng),
                    more: rng.below(10) == 0,
                    bytes: data(rng),
                },
                5 => ToMirror::Lines {
                    name: name(rng),
                    edits: vec![
                        Edit::Run {
                            from: rng.below(9) as u32,
                            count: rng.below(9) as u32,
                        },
                        Edit::New(data(rng)),
                    ],
                },
                6 => ToMirror::Add {
                    name: name(rng),
                    at: 5 * rng.below(9) as u64,
                    bytes: data(rng),
                },
                7 => ToMirror::Moved {
                    from: name(rng),
                    to: name(rng),
                },
                8 => ToMirror::Remove(name(rng)),
                9 => ToMirror::Folder("main".into()),
                10 => ToMirror::Link {
                    name: "shown".into(),
                    to: "main".into(),
                },
                _ => ToMirror::Put {
                    name: "title".into(),
                    more: false,
                    bytes: data(rng),
                },
            });
        }
        if rng.below(12) != 0 {
            messages.push(ToMirror::Done);
        }
    }
    bytes(&messages)
}

#[test]
fn no_sequence_of_messages_leaves_a_mirror_that_no_whole_round_left() {
    let mut rng = Rng(0x6b6f_6820_6361_7272);
    for _ in 0..SEQUENCES {
        let mut data = rounds(&mut rng);
        entry::carry_sequence(&data);
        // And the same with a byte of it changed, a length or a name's.
        let whole = [data.clone()];
        mutate(&mut rng, &mut data, &whole);
        entry::carry_sequence(&data);
    }
}

/// How many sequences are built: each is given to a mirror of its own, and once more changed.
const SEQUENCES: usize = 1500;

/// Rounds: each puts every seed, mutated, through every entry point (44 seeds: 220,000 messages
/// in all), and four built screens with their updates through the frames' (20,000).
const ROUNDS: usize = 5000;
