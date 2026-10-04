//! The measures taken in a child process of their own (this binary again), so that nothing else
//! the harness did is counted: a server session's memory, and the instructions the server and
//! the client retire.
//!
//! - `--footprint-child SCROLLBACK FILL SESSIONS`: makes `SESSIONS` server emulators at 40x120
//!   keeping `SCROLLBACK` lines, fills each (if `FILL` is 1) with enough lines of text to fill its
//!   scrollback and screen, takes a snapshot of each as a session holds, and prints how much the
//!   process's resident memory grew, per session, in bytes.
//! - `--instructions-child SIDE WORKLOAD [baseline]`: `emulator` feeds the workload to a server
//!   emulator in 4 KiB reads; `server` does too, and after each read takes the snapshot, diff and
//!   encoded frame a session's burst takes; `client` decodes, applies and paints those frames, as
//!   `koh connect` does. With `baseline` it makes the same inputs and does nothing with them, so that the
//!   parent can take that away. It prints what it fed: bytes for the server, frames for the
//!   client.

use std::cell::{Cell, RefCell};
use std::path::Path;
use std::process::Command;
use std::rc::Rc;
use std::time::Instant;

use anyhow::{anyhow, Context as _};
use koh::client::{BackendTerminal, ClientSession, ClientTerminal, KohBackend};
use koh::predict::{DisplayPreference, Overlay};
use koh::proto::{decode_frame, encode_frame, Frame, FrameNum, InputSeq};
use koh::terminal::{ServerTerminal, Size, TerminalScreen};

use crate::recording::Recording;
use crate::workloads::{synthetic, Workload};

pub const FOOTPRINT: &str = "--footprint-child";
pub const INSTRUCTIONS: &str = "--instructions-child";

/// Resident memory, in bytes, from `/proc/self/status`.
fn resident() -> anyhow::Result<u64> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    let kb: u64 = status
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())
        .ok_or_else(|| anyhow!("no VmRSS"))?;
    Ok(kb.saturating_mul(1024))
}

pub fn footprint_child(args: &[String]) -> anyhow::Result<()> {
    let number = |i: usize| -> anyhow::Result<usize> {
        args.get(i)
            .ok_or_else(|| anyhow!("too few arguments"))?
            .parse()
            .context("a number")
    };
    let (scrollback, fill, sessions) = (number(0)?, number(1)? == 1, number(2)?);
    let mut text = Vec::new();
    if fill {
        let workload = synthetic()
            .into_iter()
            .find(|w| w.name == "ascii-flood")
            .ok_or_else(|| anyhow!("no flood"))?;
        let lines = scrollback.saturating_add(40);
        let all: Vec<u8> = workload
            .steps
            .iter()
            .flat_map(|s| s.output.clone())
            .collect();
        let mut seen = 0usize;
        for line in all.split_inclusive(|&b| b == b'\n').cycle() {
            text.extend_from_slice(line);
            seen = seen.saturating_add(1);
            if seen >= lines {
                break;
            }
        }
    }
    let before = resident()?;
    let mut kept = Vec::new();
    for _ in 0..sessions {
        let mut emu = ServerTerminal::new(40, 120, scrollback).map_err(|e| anyhow!("{e}"))?;
        for chunk in text.chunks(4096) {
            emu.process(chunk);
        }
        let snapshot = emu.snapshot();
        kept.push((emu, snapshot));
    }
    let after = resident()?;
    let grown = after.saturating_sub(before);
    println!(
        "{}",
        grown
            .checked_div(u64::try_from(sessions.max(1)).unwrap_or(1))
            .unwrap_or(0)
    );
    drop(kept);
    Ok(())
}

/// Run a footprint child; bytes per session.
pub fn footprint(scrollback: usize, fill: bool, sessions: usize) -> anyhow::Result<u64> {
    let out = Command::new(std::env::current_exe()?)
        .arg(FOOTPRINT)
        .args([
            scrollback.to_string(),
            u8::from(fill).to_string(),
            sessions.to_string(),
        ])
        .output()?;
    anyhow::ensure!(
        out.status.success(),
        "footprint child: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .context("footprint child's answer")
}

/// The workloads instructions are counted on: each synthetic one, and `corpus`, every recording
/// at its size in turn.
pub const COUNTED: &[&str] = &[
    "ascii-flood",
    "cursor-motion",
    "scroll-region",
    "redraw-30fps",
    "corpus",
];

fn workloads(name: &str) -> anyhow::Result<Vec<Workload>> {
    if name == "corpus" {
        let corpus = Recording::load_all(Path::new("testing/corpus")).map_err(|e| anyhow!(e))?;
        return Ok(corpus.iter().map(Workload::recorded).collect());
    }
    synthetic()
        .into_iter()
        .find(|w| w.name == name)
        .map(|w| vec![w])
        .ok_or_else(|| anyhow!("no workload {name}"))
}

/// The frames a server sends for `workload`, a snapshot after each 4 KiB read: encoded, and the
/// bytes fed. With `work` false, only the bytes are made; with `frames` false, the emulator is fed
/// and no frame is made.
fn serve(
    workload: &Workload,
    work: bool,
    frames_too: bool,
) -> anyhow::Result<(Vec<Vec<u8>>, usize)> {
    let mut emu =
        ServerTerminal::new(workload.rows, workload.cols, 1000).map_err(|e| anyhow!("{e}"))?;
    let mut base = TerminalScreen::default();
    let mut frames = Vec::new();
    let mut num = FrameNum::BLANK;
    let mut fed = 0usize;
    for step in &workload.steps {
        if let Some((rows, cols)) = step.resize {
            if work {
                emu.resize(Size::new(rows, cols));
            }
        }
        for chunk in step.output.chunks(4096) {
            fed = fed.saturating_add(chunk.len());
            if !work {
                continue;
            }
            emu.process(chunk);
            drop(emu.take_host_replies());
            if !frames_too {
                continue;
            }
            let screen = emu.snapshot();
            let next = num.next();
            let frame = Frame {
                num: next,
                base: num,
                echo_ack: InputSeq::default(),
                diff: screen.diff_from(&base),
            };
            frames.push(encode_frame(&frame).map_err(|e| anyhow!("{e}"))?);
            base = screen;
            num = next;
        }
    }
    Ok((frames, fed))
}

#[derive(Clone)]
struct Sink {
    bytes: Rc<RefCell<usize>>,
    size: Rc<Cell<Size>>,
}

impl KohBackend for Sink {
    fn write_bytes(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        let mut n = self.bytes.borrow_mut();
        *n = n.saturating_add(bytes.len());
        Ok(())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
    fn enter_raw_mode(&mut self) -> std::io::Result<()> {
        Ok(())
    }
    fn leave_raw_mode(&mut self) -> std::io::Result<()> {
        Ok(())
    }
    fn size(&self) -> std::io::Result<Size> {
        Ok(self.size.get())
    }
}

/// Decode, apply and paint `frames`, as the client does.
fn paint(workload: &Workload, frames: &[Vec<u8>]) -> anyhow::Result<usize> {
    let size = Size::new(workload.rows, workload.cols);
    let sink = Sink {
        bytes: Rc::default(),
        size: Rc::new(Cell::new(size)),
    };
    let mut terminal = BackendTerminal::enter(sink.clone(), false)?;
    let mut client = ClientSession::new(DisplayPreference::Never, size);
    let now = Instant::now();
    for bytes in frames {
        let frame = decode_frame(bytes).map_err(|e| anyhow!("{e}"))?;
        let resized = frame.diff.resize;
        if let Some(size) = resized {
            sink.size.set(size);
            client.on_resize(size);
            terminal.window_resized();
        }
        client.on_frame(now, &frame);
        while client.pop_outgoing().is_some() {}
        terminal.render(client.state(), &Overlay::empty(), None)?;
    }
    let painted = *sink.bytes.borrow();
    Ok(painted)
}

pub fn instructions_child(args: &[String]) -> anyhow::Result<()> {
    let side = args.first().ok_or_else(|| anyhow!("no side"))?;
    let name = args.get(1).ok_or_else(|| anyhow!("no workload"))?;
    let baseline = args.get(2).is_some_and(|a| a == "baseline");
    let mut fed = 0usize;
    for workload in workloads(name)? {
        match side.as_str() {
            "emulator" => fed = fed.saturating_add(serve(&workload, !baseline, false)?.1),
            "server" => fed = fed.saturating_add(serve(&workload, !baseline, true)?.1),
            "client" => {
                let (frames, _) = serve(&workload, true, true)?;
                if !baseline {
                    paint(&workload, &frames)?;
                }
                fed = fed.saturating_add(frames.len());
            }
            other => return Err(anyhow!("no side {other}")),
        }
    }
    println!("{fed}");
    Ok(())
}

/// What counts instructions here.
#[derive(Clone, Copy, Debug)]
pub enum Counter {
    Perf,
    Cachegrind,
}

impl Counter {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Perf => "perf stat -e instructions:u",
            Self::Cachegrind => "valgrind --tool=cachegrind (I refs)",
        }
    }

    pub fn detect() -> Option<Self> {
        [Self::Perf, Self::Cachegrind].into_iter().find(|c| {
            c.count(Path::new("/bin/true"), &[])
                .is_ok_and(|(n, _)| n > 0)
        })
    }

    /// Run `program args`: the instructions it retired, and its stdout.
    pub fn count(self, program: &Path, args: &[String]) -> anyhow::Result<(u64, String)> {
        let mut command = match self {
            Self::Perf => {
                let mut c = Command::new("perf");
                c.args(["stat", "-x", ",", "-e", "instructions:u", "--"]);
                c
            }
            Self::Cachegrind => {
                let mut c = Command::new("valgrind");
                c.args([
                    "--tool=cachegrind",
                    "--cache-sim=no",
                    "--cachegrind-out-file=/dev/null",
                ]);
                c
            }
        };
        let out = command.arg(program).args(args).output()?;
        anyhow::ensure!(
            out.status.success(),
            "{} failed: {}",
            self.name(),
            String::from_utf8_lossy(&out.stderr)
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        let n = match self {
            Self::Perf => stderr
                .lines()
                .find(|l| l.contains("instructions"))
                .and_then(|l| l.split(',').next())
                .and_then(|n| n.trim().parse().ok()),
            Self::Cachegrind => stderr
                .lines()
                .find_map(|l| l.split("I refs:").nth(1))
                .and_then(|n| n.trim().replace(',', "").parse().ok()),
        }
        .ok_or_else(|| anyhow!("no count in {stderr}"))?;
        Ok((n, String::from_utf8_lossy(&out.stdout).into_owned()))
    }
}

/// Instructions per unit fed for `side` on `workload`: the fewest of `runs` runs less the fewest
/// of the baseline's, over what was fed.
pub fn instructions(
    counter: Counter,
    side: &str,
    workload: &str,
    runs: usize,
) -> anyhow::Result<f64> {
    let exe = std::env::current_exe()?;
    let best = |baseline: bool| -> anyhow::Result<(u64, u64)> {
        let mut args = vec![
            INSTRUCTIONS.to_owned(),
            side.to_owned(),
            workload.to_owned(),
        ];
        if baseline {
            args.push("baseline".to_owned());
        }
        let mut fewest = u64::MAX;
        let mut fed = 0;
        for _ in 0..runs {
            let (n, out) = counter.count(&exe, &args)?;
            fewest = fewest.min(n);
            fed = out.trim().parse().context("what the child fed")?;
        }
        Ok((fewest, fed))
    };
    let (work, fed) = best(false)?;
    let (base, _) = best(true)?;
    Ok(work.saturating_sub(base) as f64 / fed.max(1) as f64)
}
