//! The corpus (`testing/corpus/`, real programs' output) through the whole pipeline, as a session
//! carries it: the output cut into PTY-sized pieces, the resizes, then server snapshot → frame →
//! encode → decode → client screen → paint. After every frame the client applies, a fux-vt
//! terminal that has read every byte the client painted must show what the server's screen
//! shows: each cell's text, halves and attributes, the cursor and whether it is shown.
//!
//! The server's screen here is a fux-vt parser of its own, fed the same pieces and resizes, so a
//! fault in koh's snapshots shows as a difference too. Over a lossy link, frames are dropped and
//! the server diffs against the newest frame the client acknowledged, as koh's protocol does;
//! the newest frame of each step is resent until it arrives, as the server's retries do, so the
//! client must converge on every step's screen.

#[path = "../testing/corpus/recording.rs"]
mod recording;

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::path::Path;
use std::rc::Rc;
use std::time::{Duration, Instant};

use koh::client::{BackendTerminal, ClientSession, ClientTerminal, KohBackend};
use koh::predict::{DisplayPreference, Overlay};
use koh::proto::{decode_frame, encode_frame, ClientMsg, Frame, FrameNum, InputSeq};
use koh::terminal::{FrameHold, ServerTerminal, Size, TerminalScreen, FRAME_HOLD};
use recording::Recording;

/// The scrollback a server keeps by default (`koh serve --scrollback`).
const SCROLLBACK: usize = 1000;

/// The most bytes one read of a PTY returns here.
const PIECE: u64 = 2048;

/// A seeded random sequence (splitmix64), so a failure names the seed that reproduces it.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A number in `1..=max`.
    fn upto(&mut self, max: u64) -> u64 {
        self.next().checked_rem(max).unwrap_or(0).saturating_add(1)
    }

    /// True with probability `p`.
    fn chance(&mut self, p: f64) -> bool {
        let unit =
            f64::from(u32::try_from(self.next() >> 32).unwrap_or(u32::MAX)) / 4_294_967_296.0;
        unit < p
    }
}

/// The user's terminal, as the client's backend sees it: what was painted, and its size.
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

/// What a cell shows: its text (a printed space shows what an erased cell of its attributes does,
/// so the two count as one), whether it is either half of a wide glyph, its attributes, and its
/// hyperlink's URI and id.
type Look = (
    String,
    bool,
    bool,
    fux_vt::Attributes,
    Option<(String, Option<String>)>,
);

/// What a screen shows: its size, every cell, whether the cursor is hidden and where it is.
#[derive(Clone, Debug, PartialEq)]
struct View {
    size: (u16, u16),
    cells: Vec<Option<Look>>,
    hidden: bool,
    cursor: (u16, u16),
}

impl View {
    /// What `screen` shows. With `drawn`, as the server draws it: in the colours its program set.
    fn of(screen: &fux_vt::Screen, drawn: bool) -> Self {
        let (rows, cols) = screen.size();
        let cells = (0..rows)
            .flat_map(|row| (0..cols).map(move |col| (row, col)))
            .map(|(row, col)| {
                screen.cell(row, col).map(|cell| {
                    let text = if cell.contents() == " " {
                        String::new()
                    } else {
                        cell.contents().to_owned()
                    };
                    let mut attributes = cell.attributes();
                    if drawn {
                        attributes = koh::terminal::drawn(attributes, screen);
                    }
                    let link = screen
                        .link(row, col)
                        .map(|l| (l.uri().to_owned(), l.id().map(str::to_owned)));
                    (
                        text,
                        cell.is_wide(),
                        cell.is_wide_continuation(),
                        attributes,
                        link,
                    )
                })
            })
            .collect();
        Self {
            size: screen.size(),
            cells,
            hidden: screen.hide_cursor(),
            cursor: screen.cursor_position(),
        }
    }

    /// The first difference between what `shown` shows and this, if there is one.
    fn difference(&self, shown: &Self) -> Option<String> {
        if shown.size != self.size {
            return Some(format!("size {:?}, expected {:?}", shown.size, self.size));
        }
        let cols = usize::from(self.size.1).max(1);
        for (at, (a, b)) in shown.cells.iter().zip(&self.cells).enumerate() {
            if a != b {
                let (row, col) = (at.checked_div(cols), at.checked_rem(cols));
                return Some(format!(
                    "cell ({row:?}, {col:?}): shown {a:?}, expected {b:?}"
                ));
            }
        }
        if shown.hidden != self.hidden {
            return Some(format!(
                "cursor hidden {}, expected {}",
                shown.hidden, self.hidden
            ));
        }
        if !self.hidden && shown.cursor != self.cursor {
            return Some(format!(
                "cursor at {:?}, expected {:?}",
                shown.cursor, self.cursor
            ));
        }
        None
    }
}

/// `ms` after `now`.
fn later(now: Instant, ms: u64) -> Instant {
    now.checked_add(Duration::from_millis(ms)).unwrap_or(now)
}

/// What a replay sent and checked.
#[derive(Default)]
struct Replayed {
    frames: u64,
    applied: u64,
    wire_bytes: u64,
}

/// The server and client ends of one replay, and the terminal the client paints.
struct Session {
    server: ServerTerminal,
    /// When the server sends a screen, while a program draws a frame.
    hold: FrameHold,
    /// The server's screen, from a parser of its own, fed a byte at a time so that it sees exactly
    /// where each frame begins.
    expected: fux_vt::Parser,
    /// What the expected screen showed when the frame being drawn began, and when that was.
    frame_start: Option<(View, Instant)>,
    /// The time, which the replay moves on by a millisecond a piece.
    now: Instant,
    client: ClientSession,
    terminal: BackendTerminal<Capture>,
    capture: Capture,
    /// The user's terminal, reading every painted byte.
    shown: fux_vt::Parser,
    /// The newest frame the client acknowledged, the next frame's base.
    base: (FrameNum, TerminalScreen),
    /// Frames sent and not yet acknowledged or superseded.
    sent: VecDeque<(FrameNum, TerminalScreen)>,
    next: FrameNum,
    replayed: Replayed,
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
            // The server's parser, with its options and scrollback.
            expected: fux_vt::Parser::with_options(rows, cols, SCROLLBACK, koh::terminal::OPTIONS)
                .map_err(|e| e.to_string())?,
            hold: FrameHold::default(),
            frame_start: None,
            now: Instant::now(),
            client: ClientSession::new(DisplayPreference::Never, size),
            terminal: {
                // The user's terminal draws underline styles, as the one reading the paint does.
                let mut terminal =
                    BackendTerminal::enter(capture.clone(), false).map_err(|e| e.to_string())?;
                terminal.set_underline_styles(true);
                terminal.set_hyperlinks(true);
                terminal
            },
            capture,
            // A terminal that keeps hyperlinks, as the user's does.
            shown: fux_vt::Parser::with_options(
                rows,
                cols,
                0,
                fux_vt::Options::new().with_hyperlinks(true),
            )
            .map_err(|e| e.to_string())?,
            base: (FrameNum::BLANK, TerminalScreen::default()),
            sent: VecDeque::new(),
            next: FrameNum::BLANK.next(),
            replayed: Replayed::default(),
        })
    }

    fn resize(&mut self, rows: u16, cols: u16) -> Result<(), String> {
        let size = Size::new(rows, cols);
        self.server.resize(size);
        self.expected
            .resize(rows, cols)
            .map_err(|e| e.to_string())?;
        // The user's terminal resized itself; the client hears of it and repaints everything.
        self.capture.size.set(size);
        self.shown.resize(rows, cols).map_err(|e| e.to_string())?;
        self.client.on_resize(size);
        self.terminal.window_resized();
        Ok(())
    }

    /// The program wrote `piece`; the screen the server sends after it, if any.
    fn output(&mut self, piece: &[u8]) -> Result<Option<TerminalScreen>, String> {
        self.now = later(self.now, 1);
        self.server.process(piece);
        // The program already had its replies when it was recorded.
        drop(self.server.take_host_replies());
        for byte in piece {
            let drawing = self.expected.screen().synchronized_output();
            self.expected
                .process(std::slice::from_ref(byte))
                .map_err(|e| e.to_string())?;
            if !drawing && self.expected.screen().synchronized_output() {
                // A frame begins: the screen as it was is a whole one.
                self.frame_start = Some((View::of(self.expected.screen(), true), self.now));
            }
        }
        Ok(self.hold.after_output(&mut self.server, self.now))
    }

    /// What the user should see once `screen` arrives: while the program draws a frame, and for
    /// no longer than the hold, the screen as it was when the frame began; else the screen.
    fn expected_view(&self) -> View {
        match &self.frame_start {
            Some((view, began))
                if self.expected.screen().synchronized_output()
                    && self.now.saturating_duration_since(*began) < FRAME_HOLD =>
            {
                view.clone()
            }
            Some(_) | None => View::of(self.expected.screen(), true),
        }
    }

    /// Send a frame of `screen`, delivered unless `dropped`. Whether the client applied it.
    fn frame(&mut self, screen: &TerminalScreen, dropped: bool) -> Result<bool, String> {
        let screen = screen.clone();
        let frame = Frame {
            num: self.next,
            base: self.base.0,
            echo_ack: InputSeq::default(),
            diff: screen.diff_from(&self.base.1),
        };
        self.next = self.next.next();
        let bytes = encode_frame(&frame).map_err(|e| e.to_string())?;
        self.replayed.frames = self.replayed.frames.saturating_add(1);
        self.replayed.wire_bytes = self
            .replayed
            .wire_bytes
            .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        self.sent.push_back((frame.num, screen));
        while self.sent.len() > 16 {
            self.sent.pop_front();
        }
        if dropped {
            return Ok(false);
        }
        let frame = decode_frame(&bytes).map_err(|e| e.to_string())?;
        self.client.on_frame(Instant::now(), &frame);
        let mut applied = false;
        while let Some(msg) = self.client.pop_outgoing() {
            match msg {
                ClientMsg::Ack { frame: acked } => {
                    applied = acked == frame.num;
                    if let Some(at) = self.sent.iter().position(|(num, _)| *num == acked) {
                        let mut newer = self.sent.split_off(at);
                        if let Some(base) = newer.pop_front() {
                            self.base = base;
                        }
                        self.sent = newer;
                    }
                }
                ClientMsg::Resync => self.base = (FrameNum::BLANK, TerminalScreen::default()),
                ClientMsg::Input { .. } | ClientMsg::Resize(_) | ClientMsg::History(_) => {}
            }
        }
        if applied {
            self.replayed.applied = self.replayed.applied.saturating_add(1);
            self.terminal
                .render(self.client.state(), &Overlay::empty(), None)
                .map_err(|e| e.to_string())?;
            let painted = std::mem::take(&mut *self.capture.painted.borrow_mut());
            self.shown.process(&painted).map_err(|e| e.to_string())?;
            let expected = self.expected_view();
            if let Some(difference) = expected.difference(&View::of(self.shown.screen(), false)) {
                return Err(format!("frame {}: {difference}", frame.num.0));
            }
        }
        Ok(applied)
    }
}

/// Replay `recording` with pieces and frame boundaries from `seed`, dropping each frame with
/// probability `loss`.
fn replay(recording: &Recording, seed: u64, loss: f64) -> Result<Replayed, String> {
    let mut rng = Rng(seed);
    let mut session = Session::new(recording.rows, recording.cols)?;
    for (index, (step, output)) in recording.outputs().enumerate() {
        let at = |e: String| format!("{} seed {seed} step {index}: {e}", recording.name);
        if let Some((rows, cols)) = step.resize {
            session.resize(rows, cols).map_err(at)?;
        }
        let mut rest = output;
        while !rest.is_empty() {
            let len = usize::try_from(rng.upto(PIECE)).unwrap_or(usize::MAX);
            let (piece, after) = rest.split_at(len.min(rest.len()));
            rest = after;
            let sent = session.output(piece).map_err(at)?;
            // The server snapshots once per burst of output, not per read: a frame after some
            // pieces, and always at the step's end.
            if let Some(screen) = sent.filter(|_| !rest.is_empty() && rng.chance(0.5)) {
                let dropped = rng.chance(loss);
                session.frame(&screen, dropped).map_err(at)?;
            }
        }
        // The step's end, when the program has been quiet a while: a frame it left unfinished is
        // let go, and the step's last screen is resent until the client has it.
        session.now = later(session.now, 400);
        let screen = match session.hold.expire(&mut session.server, session.now) {
            Some(screen) => screen,
            None => session.server.snapshot(),
        };
        let mut tries = 0u32;
        while !session.frame(&screen, rng.chance(loss)).map_err(at)? {
            tries = tries.saturating_add(1);
            if tries > 100 {
                return Err(at(
                    "the client never applied the step's last frame".to_owned()
                ));
            }
        }
    }
    Ok(session.replayed)
}

fn corpus() -> Result<Vec<Recording>, String> {
    Recording::load_all(&Path::new(env!("CARGO_MANIFEST_DIR")).join("testing/corpus"))
}

/// Replay every recording with `loss`, seeds from `first`: the failures, those of [`recording::DIFFERS`] that
/// no longer differ among them, and what was sent.
fn replay_all(corpus: &[Recording], first: u64, loss: f64) -> (Vec<String>, Replayed) {
    let mut failures = Vec::new();
    let mut total = Replayed::default();
    for (seed, recording) in (first..).zip(corpus) {
        let differs = recording::DIFFERS
            .iter()
            .any(|(name, _)| *name == recording.name);
        match (replay(recording, seed, loss), differs) {
            (Ok(replayed), false) => {
                total.frames = total.frames.saturating_add(replayed.frames);
                total.applied = total.applied.saturating_add(replayed.applied);
                total.wire_bytes = total.wire_bytes.saturating_add(replayed.wire_bytes);
            }
            (Err(_), true) => {}
            (Err(e), false) => failures.push(e),
            (Ok(_), true) => failures.push(format!(
                "{} no longer differs: take it off recording::DIFFERS",
                recording.name
            )),
        }
    }
    (failures, total)
}

#[test]
fn every_recording_reads_back_as_the_server_shows_it() {
    let corpus = corpus().expect("the corpus");
    assert!(corpus.len() >= 100, "{} recordings", corpus.len());
    let (failures, total) = replay_all(&corpus, 1, 0.0);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert_eq!(total.applied, total.frames, "every frame applied");
}

#[test]
fn every_recording_converges_over_a_lossy_link() {
    let corpus = corpus().expect("the corpus");
    let (failures, total) = replay_all(&corpus, 1_000, 0.3);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    // About 30% dropped; the client still converged on every step.
    assert!(
        total.applied.saturating_mul(10) < total.frames.saturating_mul(8),
        "{} of {} frames applied",
        total.applied,
        total.frames
    );
}

#[test]
fn the_corpus_is_read_whole() {
    let corpus = corpus().expect("the corpus");
    let resizes = corpus
        .iter()
        .flat_map(|r| &r.steps)
        .filter(|s| s.resize.is_some())
        .count();
    assert_eq!(resizes, 23, "the recordings' resizes");
    for recording in &corpus {
        let last = recording.steps.last().expect("a step");
        assert_eq!(last.end, recording.bytes.len(), "{}", recording.name);
    }
    let nvim = corpus
        .iter()
        .find(|r| r.name == "nvim-split")
        .expect("nvim-split");
    assert_eq!((nvim.rows, nvim.cols), (40, 120));
    assert_eq!(nvim.steps[1].keys, b":split\r");
    assert_eq!(nvim.steps[3].keys, b"\x17w");
}
