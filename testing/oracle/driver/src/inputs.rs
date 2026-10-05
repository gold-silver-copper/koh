//! The cases the oracle runs: the corpus's recordings, as a session would carry them, and random
//! sessions built from pieces of terminal output that exercise every part of a screen and of
//! koh's diff and paint.

use crate::case::{Case, Step};
use crate::recording::Recording;

/// A seeded random sequence (splitmix64).
pub struct Rng(u64);

impl Rng {
    pub const fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A number in `0..n`, 0 if `n` is 0.
    pub fn below(&mut self, n: usize) -> usize {
        let n = u64::try_from(n).unwrap_or(u64::MAX);
        usize::try_from(self.next().checked_rem(n).unwrap_or(0)).unwrap_or(0)
    }

    /// True `percent` times in a hundred.
    pub fn percent(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }

    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> Option<&'a T> {
        items.get(self.below(items.len()))
    }
}

/// Pieces of output, each a thing a program does to a screen.
const PIECES: &[&str] = &[
    "text",
    "a line long enough to wrap on a narrow screen",
    "\r\n",
    "\n",
    "\r",
    "\x08",
    "\t",
    "\x1b[Z",
    "\x1b[2I",
    "\x1bH",
    "\x1b[3g",
    "\x1b[H",
    "\x1b[3;4H",
    "\x1b[2;9H",
    "\x1b[99;99H",
    "\x1b[A",
    "\x1b[2B",
    "\x1b[3C",
    "\x1b[D",
    "\x1b[2J",
    "\x1b[J",
    "\x1b[1J",
    "\x1b[K",
    "\x1b[1K",
    "\x1b[2K",
    "\x1b[2X",
    "\x1b[2;4r",
    "\x1b[r",
    "\x1b[2;4r\x1b[4;1H\n\n\x1b[r",
    "\x1bM",
    "\x1bD",
    "\x1b[2L",
    "\x1b[M",
    "\x1b[2S",
    "\x1b[T",
    "\x1b[2@",
    "\x1b[P",
    "\x1b[4h",
    "\x1b[4l",
    "\x1b[?7l",
    "\x1b[?7h",
    "\x1b[?6h",
    "\x1b[?6l",
    "\x1b7",
    "\x1b8",
    "\x1b[s",
    "\x1b[u",
    "\x1b[?1049h",
    "\x1b[?1049l",
    "\x1b[?47h",
    "\x1b[?47l",
    "\x1bc",
    "\x1b[!p",
    "\x1b[?25l",
    "\x1b[?25h",
    "\x1b[1m",
    "\x1b[2m",
    "\x1b[3m",
    "\x1b[4m",
    "\x1b[4:3m",
    "\x1b[5m",
    "\x1b[6m",
    "\x1b[7m",
    "\x1b[8m",
    "\x1b[9m",
    "\x1b[22m",
    "\x1b[m",
    "\x1b[31m",
    "\x1b[92m",
    "\x1b[38;5;200m",
    "\x1b[38;2;1;2;3m",
    "\x1b[44m",
    "\x1b[103m",
    "\x1b[48;5;100m",
    "\x1b[48;2;4;5;6m",
    "\x1b[58;5;9m",
    "\x1b[58;2;7;8;9m",
    "\x1b[39;49m",
    "日本語",
    "e\u{301}",
    "\u{1f468}\u{200d}\u{1f469}\u{200d}\u{1f467}",
    "\u{1f44d}\u{1f3fd}",
    "\u{1f1ef}\u{1f1f5}",
    "\u{2764}\u{fe0f}",
    "\u{301}",
    "\x1b(0lqk\x1b(B",
    "\x1b#8",
    "\x1b]2;a title\x07",
    "\x1b]1;an icon\x07",
    "\x1b]0;both\x1b\\",
    "\x1b]52;c;aGVsbG8=\x07",
    "\x07",
    "\x1b[?1h\x1b=",
    "\x1b[?1l\x1b>",
    "\x1b[?2004h",
    "\x1b[?2004l",
    "\x1b[?1000h",
    "\x1b[?1002h\x1b[?1006h",
    "\x1b[?1003h\x1b[?1005h",
    "\x1b[?9h",
    "\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?9l",
    "\x1b[c",
    "\x1b[>c",
    "\x1b[5n",
    "\x1b[6n",
    "\x1b[?6n",
    "\x1b[?2004$p",
    "\x1b[?2026h",
    "\x1b[?2026l",
    "\x1b[2 q",
    "\x1b[3b",
    "\x1b[?69h\x1b[2;5s",
    "\x1b[?69l",
];

/// Typed keys.
const KEYS: &[&[u8]] = &[
    b"a",
    b"hello",
    b" ",
    b"\x7f",
    b"\r",
    b"\x1b[D",
    b"\x1b[C",
    b"\x1bOD",
    b"\x1bOC",
    "日".as_bytes(),
    "\u{1f600}".as_bytes(),
    b"\x03",
];

/// A random session at a small size, so that edges, wraps and scrolls come often.
pub fn random(seed: u64) -> Case {
    let mut rng = Rng::new(seed);
    let rows = u16::try_from(rng.below(10)).unwrap_or(0).saturating_add(2);
    let cols = u16::try_from(rng.below(28)).unwrap_or(0).saturating_add(2);
    let mut steps = Vec::new();
    for _ in 0..rng.below(40).saturating_add(1) {
        let kind = rng.below(100);
        let step = if kind < 50 {
            let mut bytes = Vec::new();
            for _ in 0..rng.below(8).saturating_add(1) {
                if rng.percent(5) {
                    for _ in 0..rng.below(6) {
                        bytes.push(u8::try_from(rng.below(256)).unwrap_or(0));
                    }
                } else if let Some(piece) = rng.pick(PIECES) {
                    bytes.extend_from_slice(piece.as_bytes());
                }
            }
            Step::Output(bytes)
        } else if kind < 75 {
            Step::Frame {
                dropped: rng.percent(20),
            }
        } else if kind < 85 {
            let keys = rng.pick(KEYS).copied().unwrap_or_default().to_vec();
            if rng.percent(60) {
                // The program echoes it, as a shell's line editor would.
                steps.push(Step::Keys(keys.clone()));
                Step::Output(keys)
            } else {
                Step::Keys(keys)
            }
        } else if kind < 92 {
            Step::Tick(u64::try_from(rng.below(12_000)).unwrap_or(0))
        } else {
            let rows = u16::try_from(rng.below(10)).unwrap_or(0).saturating_add(2);
            let cols = u16::try_from(rng.below(28)).unwrap_or(0).saturating_add(2);
            Step::Resize(rows, cols)
        };
        steps.push(step);
    }
    steps.push(Step::Frame { dropped: false });
    Case {
        name: format!("random-{seed}"),
        rows,
        cols,
        steps,
    }
}

/// `recording` as a session carries it: each step's resize and keys, then its output in
/// PTY-sized pieces with a frame after some of them (lost `loss` percent of the time), and an
/// arriving frame at the step's end.
pub fn recorded(recording: &Recording, seed: u64, loss: usize) -> Case {
    let mut rng = Rng::new(seed);
    let mut steps = Vec::new();
    for (step, output) in recording.outputs() {
        if let Some((rows, cols)) = step.resize {
            steps.push(Step::Resize(rows, cols));
        }
        if !step.keys.is_empty() {
            steps.push(Step::Keys(step.keys.clone()));
        }
        let mut rest = output;
        while !rest.is_empty() {
            let len = rng.below(2048).saturating_add(1).min(rest.len());
            let (piece, after) = rest.split_at(len);
            rest = after;
            steps.push(Step::Output(piece.to_vec()));
            if !rest.is_empty() && rng.percent(50) {
                steps.push(Step::Frame {
                    dropped: rng.percent(loss),
                });
            }
        }
        steps.push(Step::Tick(400));
        steps.push(Step::Frame { dropped: false });
    }
    Case {
        name: format!("{}-{seed}", recording.name),
        rows: recording.rows,
        cols: recording.cols,
        steps,
    }
}
