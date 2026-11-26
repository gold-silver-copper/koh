//! The fuzz targets' entry points (`fuzz/entry.rs`) under a mutation run that every `cargo test`
//! repeats exactly: a fixed seed, a fixed number of rounds, a few seconds at most. It stands in
//! for coverage-guided fuzzing where that cannot run, and keeps the entry points compiling.
// (A test reads files of its own making.)
#![allow(clippy::disallowed_methods)]

#[path = "../fuzz/entry.rs"]
mod entry;

use koh::proto::{
    Attach, Attached, ExecServerMsg, JobInfo, KeyProof, LogMsg, Reply, Request, SessionInfo,
    ViewInput, ViewOutput, ViewSize, WaitResult,
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

/// One valid encoding of every message a peer sends.
fn seeds() -> Vec<Vec<u8>> {
    let text = |s: &str| s.to_string();
    let job = JobInfo {
        name: text("build"),
        pid: 4242,
        state: text("exited 0"),
        exit: Some(0),
        age_secs: 9,
        command: text("make -j4"),
    };
    let session = SessionInfo {
        name: text("1"),
        attached: true,
        state: text("running"),
        cols: 80,
        rows: 24,
        title: text("sh"),
        running_command: false,
        last_exit: Some(0),
        age_secs: 5,
        pane_dir: text("/tmp/koh/fux/koh-sessions/1"),
    };
    let run = 0x0123_4567_89ab_cdef_0123_4567_89ab_cdef_u128;
    vec![
        bytes(&KeyProof {
            key: [9; 32],
            signature: vec![1; 64],
        }),
        bytes(&Request::Exec {
            argv: vec![text("uname"), text("-a")],
            cwd: Some(text("~/proj")),
        }),
        bytes(&Request::Run {
            name: Some(text("build")),
            argv: vec![text("/bin/sh"), text("-c"), text("--"), text("make")],
            cwd: None,
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
            tail: 50,
            timeout_secs: Some(5),
        }),
        bytes(&Request::Attach(Attach {
            name: Some(text("3")),
            new: false,
            size: ViewSize {
                cols: 80,
                rows: 24,
                xpixel: 0,
                ypixel: 0,
            },
            argv: vec![text("vi")],
            cwd: Some(text("/tmp")),
            run: Some(run),
            client: 7,
            term: text("xterm-256color"),
            keyboard: 5,
            colours: text("background #1c1c1c\n"),
        })),
        bytes(&Attached {
            name: text("3"),
            run,
        }),
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
        bytes(&vec![session.clone(), session]),
        bytes(&WaitResult {
            timed_out: true,
            exit: 124,
            tail: text("tail"),
            detail: text("timed out"),
        }),
        bytes(&ViewInput::Bytes(b"ls\r".to_vec())),
        bytes(&ViewOutput::Bytes(b"\x1b[2J".to_vec())),
    ]
}

const EDGES: [u8; 8] = [0x00, 0x01, 0x7f, 0x80, 0xff, b'/', b'.', b'\n'];
/// Each round puts every seed, mutated, through every entry point.
const ROUNDS: usize = 5000;

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

#[test]
fn no_mutated_message_panics_a_decoder() {
    let seeds = seeds();
    let run = |data: &[u8]| {
        entry::to_server(data);
        entry::to_client(data);
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
    }
}
