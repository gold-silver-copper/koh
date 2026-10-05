//! What the scoreboard runs: the corpus's recordings, and synthetic workloads that stand for what
//! a remote shell carries most (a flood of text, cursor motion, a scroll region, a full-screen
//! redraw 30 times a second), and the script that plays any of them as the program.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::recording::Recording;

/// One step: the terminal resized first if `resize` says so, then the program wrote `output`.
#[derive(Clone, Debug)]
pub struct Step {
    pub resize: Option<(u16, u16)>,
    pub output: Vec<u8>,
}

/// A workload: a size and steps. A gated workload's steps are written one at a time, each when
/// the harness types for it (as the recordings were made); a timed one's are written by the
/// script itself, `every` apart.
#[derive(Clone, Debug)]
pub struct Workload {
    pub name: String,
    pub about: String,
    pub rows: u16,
    pub cols: u16,
    pub steps: Vec<Step>,
    pub every: Option<Duration>,
}

impl Workload {
    pub fn bytes(&self) -> usize {
        self.steps.iter().map(|s| s.output.len()).sum()
    }

    pub fn recorded(recording: &Recording) -> Self {
        Self {
            name: recording.name.clone(),
            about: String::new(),
            rows: recording.rows,
            cols: recording.cols,
            steps: recording
                .outputs()
                .map(|(step, output)| Step {
                    resize: step.resize,
                    output: output.to_vec(),
                })
                .collect(),
            every: None,
        }
    }

    /// The script that plays this workload, written into `dir` with each step's bytes. It puts
    /// the PTY in raw mode, so the bytes reach the emulator as written; waits for the workload's
    /// size before each step; logs `N written` after each step and `done` after the last to
    /// `dir/log`; and then idles. A gated step, and a timed workload's first, waits for a 0x01
    /// typed, which no reply to a query contains.
    pub fn script(&self, dir: &Path) -> std::io::Result<PathBuf> {
        std::fs::create_dir_all(dir)?;
        let log = dir.join("log");
        let _ = std::fs::remove_file(&log);
        let mut text = String::from("stty raw -echo\n");
        let mut size = (self.rows, self.cols);
        for (index, step) in self.steps.iter().enumerate() {
            let file = dir.join(format!("{index}.bin"));
            std::fs::write(&file, &step.output)?;
            // Every step of a gated workload waits for its 0x01, and the first of a timed one, so
            // that nothing is written before the harness has counted the connection's setup.
            match self.every {
                Some(every) if index > 0 => {
                    let _ = writeln!(text, "sleep {}", every.as_secs_f64());
                }
                Some(_) | None => text.push_str(
                    "while [ \"$(dd bs=1 count=1 2>/dev/null | od -An -tx1 | tr -d ' ')\" != 01 ]; \
                     do :; done\n",
                ),
            }
            if let Some(resize) = step.resize {
                size = resize;
            }
            let (rows, cols) = size;
            let _ = writeln!(
                text,
                "while [ \"$(stty size)\" != \"{rows} {cols}\" ]; do sleep 0.01; done"
            );
            let _ = writeln!(text, "cat '{}'", file.display());
            let _ = writeln!(text, "echo {index} written >> '{}'", log.display());
        }
        let _ = writeln!(text, "echo done >> '{}'", log.display());
        text.push_str("while :; do sleep 60; done\n");
        let path = dir.join("replay.sh");
        std::fs::write(&path, text)?;
        Ok(path)
    }
}

/// Whether the script in `dir` logged `line`.
pub fn logged(dir: &Path, line: &str) -> bool {
    std::fs::read_to_string(dir.join("log")).is_ok_and(|log| log.lines().any(|l| l == line))
}

/// A seeded random sequence (splitmix64).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next().checked_rem(n).unwrap_or(0)
    }
}

/// Words for synthetic text.
const WORDS: &[&str] = &[
    "the", "quick", "remote", "shell", "frame", "screen", "cursor", "packet", "loss", "echo",
    "terminal", "koh", "mosh", "row", "diff", "stream", "latency", "byte", "glyph", "scroll",
];

fn line(rng: &mut Rng, cols: u16) -> String {
    let mut out = String::new();
    while out.len() < usize::from(cols).saturating_sub(12) {
        let word = WORDS
            .get(usize::try_from(rng.below(20)).unwrap_or(0))
            .copied()
            .unwrap_or("x");
        out.push_str(word);
        out.push(' ');
    }
    out
}

const ROWS: u16 = 40;
const COLS: u16 = 120;

/// The synthetic workloads, at 40x120.
pub fn synthetic() -> Vec<Workload> {
    let mut rng = Rng(1);
    let mut flood = String::new();
    while flood.len() < 1 << 20 {
        flood.push_str(&line(&mut rng, COLS));
        flood.push_str("\r\n");
    }
    let mut motion = String::from("\x1b[2J");
    while motion.len() < 1 << 18 {
        let (row, col) = (
            rng.below(40).saturating_add(1),
            rng.below(100).saturating_add(1),
        );
        let _ = write!(motion, "\x1b[{row};{col}H{}", rng.below(1_000_000));
    }
    let mut region = String::from("\x1b[2J\x1b[1;1Hheader\x1b[40;1Hfooter\x1b[2;39r\x1b[39;1H");
    while region.len() < 1 << 18 {
        region.push_str("\r\n");
        region.push_str(&line(&mut rng, COLS));
    }
    region.push_str("\x1b[r");
    let redraw: Vec<Step> = (0..150u32)
        .map(|frame| {
            let mut out = String::from("\x1b[H");
            for row in 0..ROWS {
                let _ = write!(out, "\x1b[{};1H\x1b[3{}m", row.saturating_add(1), row % 7);
                let _ = write!(out, "{frame:>6} {row:>3} ");
                out.push_str(&line(&mut rng, COLS.saturating_sub(12)));
                out.push_str("\x1b[K");
            }
            out.push_str("\x1b[m");
            Step {
                resize: None,
                output: out.into_bytes(),
            }
        })
        .collect();
    let one = |output: String| {
        vec![Step {
            resize: None,
            output: output.into_bytes(),
        }]
    };
    vec![
        Workload {
            name: "ascii-flood".into(),
            about: "1 MiB of lines of text, scrolling".into(),
            rows: ROWS,
            cols: COLS,
            steps: one(flood),
            every: None,
        },
        Workload {
            name: "cursor-motion".into(),
            about: "256 KiB of numbers written at random places".into(),
            rows: ROWS,
            cols: COLS,
            steps: one(motion),
            every: None,
        },
        Workload {
            name: "scroll-region".into(),
            about: "256 KiB of lines scrolling between a header and a footer".into(),
            rows: ROWS,
            cols: COLS,
            steps: one(region),
            every: None,
        },
        Workload {
            name: "redraw-30fps".into(),
            about: "the whole screen redrawn 30 times a second for 5 s, as a dashboard does".into(),
            rows: ROWS,
            cols: COLS,
            steps: redraw,
            every: Some(Duration::from_millis(33)),
        },
    ]
}
