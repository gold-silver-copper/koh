//! One side of koh's oracle: koh at one tree, running the driver's cases through koh's public
//! API as a session would, and printing what it saw. The driver runs this binary built at the
//! working tree and built at a commit, gives both the same cases, and compares what they print.
//!
//! A case is lines on stdin, ended by `end`:
//!
//! - `case ROWS COLS`: a fresh server and client at that size;
//! - `output HEX`: the program wrote these bytes;
//! - `resize ROWS COLS`: the user's terminal resized, and the server with it;
//! - `frame DROPPED`: the server snapshots and sends a frame, lost on the way if `DROPPED` is 1;
//! - `keys HEX`: the user typed these bytes;
//! - `tick MS`: this much time passed.
//!
//! After each step it prints `step N`, then what the step gave, each line once:
//!
//! - `paint HEX`: the bytes the client painted (it paints after every step, as its loop does when
//!   anything changed, with the status line its tick reports);
//! - `replies HEX`: the server's answers to the program's queries;
//! - `sent MSG`: a message the client sent;
//! - `outcome OUTCOME`: what the client made of typed bytes;
//! - `bytes N`: a frame's size on the wire, compressed, which the driver counts and does not
//!   compare.
//!
//! Then `end`. An error ends the process, which the driver reports as a difference.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::fmt::Write as _;
use std::io::{BufRead, Write};
use std::process::ExitCode;
use std::rc::Rc;
use std::time::{Duration, Instant};

use koh::client::{BackendTerminal, ClientSession, ClientTerminal, KohBackend};
use koh::predict::DisplayPreference;
use koh::proto::{decode_frame, encode_frame, ClientMsg, Frame, FrameNum, InputSeq};
use koh::terminal::{ServerTerminal, Size, TerminalScreen};

/// The scrollback a server keeps by default.
const SCROLLBACK: usize = 1000;

/// The frames a server keeps unacknowledged, as koh's `FRAME_WINDOW`.
const WINDOW: usize = 16;

/// The user's terminal: what was painted, and its size.
#[derive(Clone)]
struct Capture {
    painted: Rc<RefCell<Vec<u8>>>,
    size: Rc<Cell<Size>>,
}

impl KohBackend for Capture {
    fn write_bytes(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.painted.borrow_mut().extend_from_slice(bytes);
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

/// A server and a client joined by frames and messages, and the terminal the client paints.
struct Session {
    server: ServerTerminal,
    client: ClientSession,
    terminal: BackendTerminal<Capture>,
    capture: Capture,
    /// The newest frame the client acknowledged, the next frame's base.
    base: (FrameNum, TerminalScreen),
    sent: VecDeque<(FrameNum, TerminalScreen)>,
    next: FrameNum,
    /// The newest input the server received, which frames acknowledge as echoed.
    echoed: InputSeq,
    start: Instant,
    elapsed: Duration,
}

impl Session {
    fn new(rows: u16, cols: u16) -> Result<Self, String> {
        let size = Size::new(rows, cols);
        let capture = Capture {
            painted: Rc::default(),
            size: Rc::new(Cell::new(size)),
        };
        Ok(Self {
            server: ServerTerminal::new(rows, cols, SCROLLBACK).map_err(|e| e.to_string())?,
            client: ClientSession::new(DisplayPreference::Always, size),
            terminal: BackendTerminal::enter(capture.clone(), false).map_err(|e| e.to_string())?,
            capture,
            base: (FrameNum::BLANK, TerminalScreen::default()),
            sent: VecDeque::new(),
            next: FrameNum::BLANK.next(),
            echoed: InputSeq::default(),
            start: Instant::now(),
            elapsed: Duration::ZERO,
        })
    }

    fn now(&self) -> Instant {
        self.start.checked_add(self.elapsed).unwrap_or(self.start)
    }

    /// Run one step, writing what it gave to `out`.
    fn step(&mut self, step: &str, out: &mut String) -> Result<(), String> {
        let mut words = step.split(' ');
        let verb = words.next().unwrap_or_default();
        let mut arg = || {
            words
                .next()
                .ok_or_else(|| format!("{verb}: too few arguments"))
        };
        match verb {
            "output" => {
                self.server.process(&unhex(arg()?)?);
                let replies = self.server.take_host_replies();
                if !replies.is_empty() {
                    let _ = writeln!(out, "replies {}", hex(&replies));
                }
            }
            "resize" => {
                let rows = number(arg()?)?;
                let cols = number(arg()?)?;
                let size = Size::new(rows, cols);
                self.server.resize(size);
                self.capture.size.set(size);
                self.client.on_resize(size);
                self.terminal.window_resized();
            }
            "frame" => self.frame(arg()? == "1", out)?,
            "keys" => {
                let outcome = self.client.on_input(self.now(), &unhex(arg()?)?);
                let _ = writeln!(out, "outcome {outcome:?}");
            }
            "tick" => {
                let ms: u64 = arg()?.parse().map_err(|e| format!("tick: {e}"))?;
                self.elapsed = self.elapsed.saturating_add(Duration::from_millis(ms));
            }
            other => return Err(format!("unknown step {other:?}")),
        }
        let tick = self.client.on_tick(self.now(), None);
        self.drain(out);
        self.terminal
            .render(
                self.client.state(),
                &self.client.overlay(),
                tick.status.as_deref(),
            )
            .map_err(|e| e.to_string())?;
        let painted = std::mem::take(&mut *self.capture.painted.borrow_mut());
        if !painted.is_empty() {
            let _ = writeln!(out, "paint {}", hex(&painted));
        }
        Ok(())
    }

    /// Snapshot the server and send the frame, delivering it unless `dropped`.
    fn frame(&mut self, dropped: bool, out: &mut String) -> Result<(), String> {
        let screen = self.server.snapshot();
        let frame = Frame {
            num: self.next,
            base: self.base.0,
            echo_ack: self.echoed,
            diff: screen.diff_from(&self.base.1),
        };
        self.next = self.next.next();
        #[cfg(koh_frame_base)]
        let bytes = encode_frame(&frame, &self.base.1).map_err(|e| e.to_string())?;
        #[cfg(not(koh_frame_base))]
        let bytes = encode_frame(&frame).map_err(|e| e.to_string())?;
        let _ = writeln!(out, "bytes {}", bytes.len());
        self.sent.push_back((frame.num, screen));
        while self.sent.len() > WINDOW {
            self.sent.pop_front();
        }
        if !dropped {
            #[cfg(koh_frame_base)]
            let frame = decode_frame(&bytes, &self.base.1).map_err(|e| e.to_string())?;
            #[cfg(not(koh_frame_base))]
            let frame = decode_frame(&bytes).map_err(|e| e.to_string())?;
            self.client.on_frame(self.now(), &frame);
            // The server takes the frame's delivery as its acknowledgement.
            #[cfg(koh_delivery_ack)]
            self.ack(frame.num);
        }
        Ok(())
    }

    /// The client has frame `frame`: the frames before it are no bases any more.
    fn ack(&mut self, frame: FrameNum) {
        if let Some(at) = self.sent.iter().position(|(num, _)| *num == frame) {
            let mut newer = self.sent.split_off(at);
            if let Some(base) = newer.pop_front() {
                self.base = base;
            }
            self.sent = newer;
        }
    }

    /// Deliver the client's messages to the server.
    fn drain(&mut self, out: &mut String) {
        while let Some(msg) = self.client.pop_outgoing() {
            let line = format!("{msg:?}");
            // Scrollback requests are new (a side at an older commit has none), and change
            // nothing the user's terminal shows until the user opens the view. Acknowledgements
            // are the transport's business: a later commit takes a frame's delivery as one and
            // sends them only to nudge.
            if !line.starts_with("History") && !line.starts_with("Ack") {
                let _ = writeln!(out, "sent {line}");
            }
            // Matched with `if let`, not `match`, so the side builds against a commit whose
            // messages are fewer or more.
            if let ClientMsg::Ack { frame } = msg {
                self.ack(frame);
            } else if let ClientMsg::Input { seq, .. } = msg {
                self.echoed = seq;
            } else if matches!(msg, ClientMsg::Resync) {
                self.base = (FrameNum::BLANK, TerminalScreen::default());
            }
        }
    }
}

fn number(word: &str) -> Result<u16, String> {
    word.parse().map_err(|e| format!("{word:?}: {e}"))
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn unhex(text: &str) -> Result<Vec<u8>, String> {
    let digits = text.as_bytes();
    digits
        .chunks(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .filter(|pair| pair.len() == 2)
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or_else(|| format!("bad hex {text:?}"))
        })
        .collect()
}

fn run() -> Result<(), String> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout().lock();
    let mut session: Option<Session> = None;
    let mut index = 0usize;
    for line in stdin.lock().lines() {
        let line = line.map_err(|e| e.to_string())?;
        let mut out = String::new();
        if let Some(size) = line.strip_prefix("case ") {
            let (rows, cols) = size.split_once(' ').ok_or("case: no size")?;
            session = Some(Session::new(number(rows)?, number(cols)?)?);
            index = 0;
        } else if line == "end" {
            session = None;
            out.push_str("end\n");
        } else {
            let session = session.as_mut().ok_or("a step outside a case")?;
            let _ = writeln!(out, "step {index}");
            index = index.saturating_add(1);
            session.step(&line, &mut out)?;
        }
        stdout
            .write_all(out.as_bytes())
            .map_err(|e| e.to_string())?;
        if line == "end" {
            stdout.flush().map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("koh-oracle-side: {e}");
            ExitCode::FAILURE
        }
    }
}
