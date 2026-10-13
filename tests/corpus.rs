//! The corpus (`testing/corpus/`, real programs' output) through the whole pipeline, as a session
//! carries it: the output cut into PTY-sized pieces, the resizes, then server snapshot → frame →
//! encode → decode → client screen → paint. After every frame the client applies, a fux-vt
//! terminal that has read every byte the client painted must show what the server's screen
//! shows: each cell's text, halves and attributes, the cursor and whether it is shown, the mouse
//! reporting, the title and icon, the clipboard, and a bell for each frame that rang one. The
//! client's copy of the screen must hold the program's input modes.
//!
//! The server's screen here is a fux-vt parser of its own, fed the same pieces and resizes, so a
//! fault in koh's snapshots shows as a difference too. Over a lossy link, frames are dropped and
//! the server diffs against the newest frame the client acknowledged, as koh's protocol does;
//! the newest frame of each step is resent until it arrives, as the server's retries do, so the
//! client must converge on every step's screen. Random sessions on small screens join the
//! recordings, for the edges no program happened to reach.
#![forbid(clippy::disallowed_methods)]

#[path = "../testing/corpus/recording.rs"]
mod recording;

use std::cell::{Cell, RefCell};
use std::path::Path;
use std::rc::Rc;
use std::time::{Duration, Instant};

use koh::client::WindowState;
use koh::client::{BackendTerminal, ClientSession, ClientTerminal, KohBackend};
use koh::predict::Overlay;
use koh::proto::{
    decode_server, encode_client, ClientDecoder, ClientMsg, Frame, FrameEncoder, FrameNum,
    InputSeq, ServerMsg,
};
use koh::terminal::{FrameHold, Modes, ServerTerminal, Size, TerminalScreen, FRAME_HOLD};
use recording::Recording;

/// The scrollback a server keeps by default (`koh serve --scrollback`).
const SCROLLBACK: usize = 1000;

/// The most bytes one read of a PTY returns here.
const PIECE: u64 = 2048;

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

/// The client prefixes the title it mirrors, and an icon equal to it.
const TITLE_PREFIX: &str = "[koh] ";

/// What a terminal was told beside its grid, from fux-vt's events.
#[derive(Clone, Debug, Default, PartialEq)]
struct Said {
    title: String,
    icon: String,
    /// Whether a frame the client applied had either set: until then the user's title is left
    /// alone.
    named: bool,
    clipboard: String,
    bells: u64,
}

impl fux_vt::Sink for Said {
    fn event(&mut self, event: fux_vt::Event<'_>) {
        let text = |bytes: &[u8]| String::from_utf8_lossy(bytes).into_owned();
        match event {
            fux_vt::Event::Title(title) => self.title = text(title),
            fux_vt::Event::IconName(icon) => self.icon = text(icon),
            fux_vt::Event::Clipboard { data, .. } => self.clipboard = text(data),
            fux_vt::Event::Bell => self.bells = self.bells.saturating_add(1),
            fux_vt::Event::ColorQuery { .. } | _ => {}
        }
    }
}

/// What a screen shows: its size, every cell, whether the cursor is hidden and where it is, its
/// modes, and what it was told beside the grid.
#[derive(Clone, Debug, PartialEq)]
struct View {
    size: (u16, u16),
    cells: Vec<Option<Look>>,
    hidden: bool,
    cursor: (u16, u16),
    modes: Modes,
    said: Said,
}

impl View {
    /// What `screen`, told `said`, shows. With `drawn`, as the server draws it: in the colours
    /// its program set.
    fn of(screen: &fux_vt::Screen, drawn: bool, said: &Said) -> Self {
        let (rows, cols) = screen.size().into();
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
                        attributes = koh::terminal::test_support::drawn(attributes, screen);
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
            size: screen.size().into(),
            cells,
            hidden: !screen.mode(fux_vt::Mode::ShowCursor),
            cursor: screen.cursor_position(),
            modes: Modes {
                hide_cursor: !screen.mode(fux_vt::Mode::ShowCursor),
                application_cursor: screen.mode(fux_vt::Mode::ApplicationCursor),
                application_keypad: screen.mode(fux_vt::Mode::ApplicationKeypad),
                bracketed_paste: screen.mode(fux_vt::Mode::BracketedPaste),
                mouse_mode: screen.mouse_protocol_mode(),
                mouse_encoding: screen.mouse_protocol_encoding(),
                alternate: screen.mode(fux_vt::Mode::AlternateScreen),
            },
            said: said.clone(),
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
        // The mouse is reported as the program asked, always in SGR; the other input modes stay
        // the client's, which encodes keys and pastes on the server.
        let mouse = self.modes.mouse_mode;
        let sgr = mouse == fux_vt::MouseProtocolMode::None
            || shown.modes.mouse_encoding == fux_vt::MouseProtocolEncoding::Sgr;
        if shown.modes.mouse_mode != mouse || !sgr {
            return Some(format!("mouse {:?}, expected {mouse:?}", shown.modes));
        }
        let (title, icon) = match &self.said {
            Said { named: false, .. } => (String::new(), String::new()),
            Said { title, icon, .. } if icon == title => (
                format!("{TITLE_PREFIX}{title}"),
                format!("{TITLE_PREFIX}{icon}"),
            ),
            Said { title, icon, .. } => (format!("{TITLE_PREFIX}{title}"), icon.clone()),
        };
        let told = (shown.said.title.as_str(), shown.said.icon.as_str());
        if told != (title.as_str(), icon.as_str()) {
            return Some(format!(
                "title and icon {told:?}, expected {title:?} {icon:?}"
            ));
        }
        (shown.said.clipboard != self.said.clipboard).then(|| {
            format!(
                "clipboard {:?}, expected {:?}",
                shown.said.clipboard, self.said.clipboard
            )
        })
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
    /// where each frame begins, and what it was told beside it.
    expected: fux_vt::Parser,
    said: Said,
    /// What the expected screen showed when the frame being drawn began, and when that was.
    frame_start: Option<(View, Instant)>,
    /// The time, which the replay moves on by a millisecond a piece.
    now: Instant,
    client: ClientSession,
    terminal: BackendTerminal<Capture>,
    capture: Capture,
    /// The user's terminal, reading every painted byte, and what it was told beside the grid.
    shown: fux_vt::Parser,
    shown_said: Said,
    /// The bells the server's screen had rung when the client last applied a frame, and the
    /// bells the user's terminal should have rung by then: one for each frame that rang any.
    bells: (u64, u64),
    /// Whether a frame the client applied had a title or icon.
    named: bool,
    /// The newest frame the client acknowledged, the next frame's base.
    base: (FrameNum, TerminalScreen),
    /// Frames sent and not yet acknowledged or superseded.
    sent: Vec<(FrameNum, TerminalScreen)>,
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
            expected: fux_vt::Parser::with_options(
                fux_vt::Size::new(rows, cols).map_err(|e| e.to_string())?,
                SCROLLBACK,
                koh::terminal::OPTIONS,
            )
            .map_err(|e| e.to_string())?,
            said: Said::default(),
            hold: FrameHold::default(),
            frame_start: None,
            now: Instant::now(),
            client: ClientSession::new(size),
            terminal: {
                // The user's terminal draws underline styles, as the one reading the paint does,
                // and takes the clipboard. The client came before anything was set or rang.
                let mut terminal =
                    BackendTerminal::enter(capture.clone(), true).map_err(|e| e.to_string())?;
                terminal.set_underline_styles(true);
                terminal.set_hyperlinks(true);
                terminal.prime(WindowState {
                    title: "",
                    icon: "",
                    clipboard: "",
                    bell_count: 0,
                });
                terminal
            },
            capture,
            // A terminal that keeps hyperlinks, as the user's does.
            shown: fux_vt::Parser::with_options(
                fux_vt::Size::new(rows, cols).map_err(|e| e.to_string())?,
                0,
                fux_vt::Options::new()
                    .with(fux_vt::Feature::Hyperlinks)
                    .with(fux_vt::Feature::Events),
            )
            .map_err(|e| e.to_string())?,
            shown_said: Said::default(),
            bells: (0, 0),
            named: false,
            base: (FrameNum::BLANK, TerminalScreen::default()),
            sent: Vec::new(),
            next: FrameNum::BLANK.next(),
            replayed: Replayed::default(),
        })
    }

    fn resize(&mut self, rows: u16, cols: u16) -> Result<(), String> {
        let size = Size::new(rows, cols);
        self.server.resize(size);
        self.expected
            .resize(fux_vt::Size::new(rows, cols).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        // The user's terminal resized itself; the client hears of it and repaints everything.
        self.capture.size.set(size);
        self.shown
            .resize(fux_vt::Size::new(rows, cols).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
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
            let drawing = self
                .expected
                .screen()
                .mode(fux_vt::Mode::SynchronizedOutput);
            self.expected
                .process_with(std::slice::from_ref(byte), &mut self.said)
                .map_err(|e| e.to_string())?;
            if !drawing
                && self
                    .expected
                    .screen()
                    .mode(fux_vt::Mode::SynchronizedOutput)
            {
                // A frame begins: the screen as it was is a whole one.
                self.frame_start =
                    Some((View::of(self.expected.screen(), true, &self.said), self.now));
            }
        }
        Ok(self.hold.after_output(&mut self.server, self.now))
    }

    /// What the user should see once `screen` arrives: while the program draws a frame, and for
    /// no longer than the hold, the screen as it was when the frame began; else the screen.
    fn expected_view(&self) -> View {
        match &self.frame_start {
            Some((view, began))
                if self
                    .expected
                    .screen()
                    .mode(fux_vt::Mode::SynchronizedOutput)
                    && self.now.saturating_duration_since(*began) < FRAME_HOLD =>
            {
                view.clone()
            }
            Some(_) | None => View::of(self.expected.screen(), true, &self.said),
        }
    }

    /// The client has frame `acked`: the frames before it are no bases any more.
    fn ack(&mut self, acked: FrameNum) {
        if let Some(at) = self.sent.iter().position(|(num, _)| *num == acked) {
            let mut newer = self.sent.split_off(at);
            if !newer.is_empty() {
                self.base = newer.remove(0);
            }
            self.sent = newer;
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
        let bytes = FrameEncoder::default()
            .encode(&frame, &self.base.1)
            .map_err(|e| e.to_string())?;
        self.replayed.frames = self.replayed.frames.saturating_add(1);
        self.replayed.wire_bytes = self
            .replayed
            .wire_bytes
            .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        self.sent.push((frame.num, screen));
        while self.sent.len() > 16 {
            self.sent.remove(0);
        }
        if dropped {
            return Ok(false);
        }
        let ServerMsg::Frame { base, rows, body } =
            decode_server(&bytes).map_err(|e| e.to_string())?
        else {
            return Err("history for a frame".to_owned());
        };
        self.client
            .on_frame_stream(Instant::now(), base, &rows, &body);
        let applied = self
            .sent
            .last()
            .is_some_and(|(_, screen)| self.client.state() == screen);
        // Delivered: the server takes that as the acknowledgement (or the client's own `Ack`, a
        // nudge, below).
        self.ack(frame.num);
        while let Some(msg) = self.client.pop_outgoing() {
            match msg {
                ClientMsg::Ack { frame: acked } => self.ack(acked),
                ClientMsg::Resync => self.base = (FrameNum::BLANK, TerminalScreen::default()),
                ClientMsg::Keys { .. }
                | ClientMsg::Colours(_)
                | ClientMsg::Resize(_)
                | ClientMsg::History(_) => {}
            }
        }
        if applied {
            self.replayed.applied = self.replayed.applied.saturating_add(1);
            self.terminal
                .render(self.client.state(), &Overlay::default(), None)
                .map_err(|e| e.to_string())?;
            let painted = std::mem::take(&mut *self.capture.painted.borrow_mut());
            self.shown
                .process_with(&painted, &mut self.shown_said)
                .map_err(|e| e.to_string())?;
            let mut expected = self.expected_view();
            self.named |= !(expected.said.title.is_empty() && expected.said.icon.is_empty());
            expected.said.named = self.named;
            let shown = View::of(self.shown.screen(), false, &self.shown_said);
            if let Some(difference) = expected.difference(&shown) {
                return Err(format!("frame {}: {difference}", frame.num.0));
            }
            let held = self.client.state().screen().modes();
            if held != expected.modes {
                return Err(format!(
                    "frame {}: the client holds modes {held:?}, expected {:?}",
                    frame.num.0, expected.modes
                ));
            }
            if expected.said.bells > self.bells.0 {
                self.bells = (expected.said.bells, self.bells.1.saturating_add(1));
            }
            if self.shown_said.bells != self.bells.1 {
                return Err(format!(
                    "frame {}: {} bells rung, expected {}",
                    frame.num.0, self.shown_said.bells, self.bells.1
                ));
            }
        }
        Ok(applied)
    }
}

/// Replay `recording` with pieces and frame boundaries from `seed`, dropping each frame with
/// probability `loss`.
fn replay(recording: &Recording, seed: u64, loss: f64) -> Result<Replayed, String> {
    let mut rng = koh_testkit::Rng(seed);
    let mut session = Session::new(recording.rows, recording.cols)?;
    for (index, (step, output)) in recording.outputs().enumerate() {
        let at = |e: String| format!("{} seed {seed} step {index}: {e}", recording.name);
        if let Some((rows, cols)) = step.resize {
            session.resize(rows, cols).map_err(at)?;
        }
        let mut rest = output;
        while !rest.is_empty() {
            let len = usize::try_from(rng.below(PIECE).saturating_add(1)).unwrap_or(usize::MAX);
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

/// Replay every recording with `loss`, seeds from `first`: the failures, and what was sent.
fn replay_all(corpus: &[Recording], first: u64, loss: f64) -> (Vec<String>, Replayed) {
    let mut failures = Vec::new();
    let mut total = Replayed::default();
    for (seed, recording) in (first..).zip(corpus) {
        match replay(recording, seed, loss) {
            Ok(replayed) => {
                total.frames = total.frames.saturating_add(replayed.frames);
                total.applied = total.applied.saturating_add(replayed.applied);
                total.wire_bytes = total.wire_bytes.saturating_add(replayed.wire_bytes);
            }
            Err(e) => failures.push(e),
        }
    }
    (failures, total)
}

/// Every recording, read whole (its steps to its last byte, its resizes too), reads back as the
/// server shows it.
#[test]
fn every_recording_reads_back_as_the_server_shows_it() {
    let corpus = corpus().expect("the corpus");
    assert!(corpus.len() >= 100, "{} recordings", corpus.len());
    for recording in &corpus {
        let end = recording.steps.last().map(|step| step.end);
        assert_eq!(end, Some(recording.bytes.len()), "{}", recording.name);
    }
    assert!(corpus
        .iter()
        .flat_map(|r| &r.steps)
        .any(|s| s.resize.is_some()));
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

/// What a random session's program writes: text of every width, every kind of attribute and
/// link, cursor moves, scrolling in and out of regions, inserting and deleting, erasing, the
/// alternate screen, every input mode, the title, icon, clipboard and bell, and frames drawn in
/// synchronized output.
const PIECES: [&str; 49] = [
    "ab",
    "abcdefghijklmnopqrstuvwxyz0123",
    "日本",
    "e\u{301}",
    "\u{302}",
    "\t",
    "\r\n",
    "\x08",
    "\x1b[1;31m",
    "\x1b[4:3;58;5;9m",
    "\x1b[2;7;38;2;1;2;3;48;5;200m",
    "\x1b[m",
    "\x1b]8;;https://koh.example/\x1b\\L\x1b]8;;\x1b\\",
    "\x1b[H",
    "\x1b[3;5H",
    "\x1b[A",
    "\x1b[9C",
    "\x1bM",
    "\x1b[2;4r",
    "\x1b[r",
    "\x1b[S",
    "\x1b[2T",
    "\x1b[L",
    "\x1b[M",
    "\x1b[2@",
    "\x1b[P",
    "\x1b[4h",
    "\x1b[4l",
    "\x1b[K",
    "\x1b[1J",
    "\x1b[2J",
    "\x1b[?1049h",
    "\x1b[?1049l",
    "\x1b[?25l",
    "\x1b[?25h",
    "\x1b[?1h\x1b=",
    "\x1b[?1l\x1b>",
    "\x1b[?2004h",
    "\x1b[?2004l",
    "\x1b[?1002h\x1b[?1006h",
    "\x1b[?1003h\x1b[?1005h",
    "\x1b[?1003l",
    "\x1b]0;both\x07",
    "\x1b]2;title\x07\x1b]1;icon\x07",
    "\x1b]52;c;aGk=\x07",
    "\x1b]52;c;?\x07",
    "\x07",
    "\x1b[?2026h",
    "\x1b[?2026l",
];

/// A small screen: 2 to 11 rows by 2 to 29 columns.
fn small_size(rng: &mut koh_testkit::Rng) -> (u16, u16) {
    let mut below = |n: u64, least: u16| {
        u16::try_from(rng.below(n))
            .unwrap_or(0)
            .saturating_add(least)
    };
    (below(10, 2), below(28, 2))
}

/// A random session from `seed` on a small screen, sometimes resized.
fn random_session(seed: u64) -> Recording {
    let mut rng = koh_testkit::Rng(seed);
    let (rows, cols) = small_size(&mut rng);
    let (mut steps, mut bytes) = (Vec::new(), Vec::new());
    for _ in 0..30 {
        let resize = rng.chance(0.1).then(|| small_size(&mut rng));
        for _ in 0..=rng.below(8) {
            let at = rng.below(u64::try_from(PIECES.len()).unwrap_or(1));
            let piece = PIECES.get(usize::try_from(at).unwrap_or(0)).unwrap_or(&"");
            bytes.extend_from_slice(piece.as_bytes());
        }
        steps.push(recording::Step {
            resize,
            keys: Vec::new(),
            end: bytes.len(),
        });
    }
    Recording {
        name: format!("random session {seed}"),
        rows,
        cols,
        steps,
        bytes,
    }
}

#[test]
fn random_small_sessions_read_back_as_the_server_shows_them() {
    let sessions: Vec<Recording> = (0..200).map(random_session).collect();
    for loss in [0.0, 0.3] {
        let (failures, _) = replay_all(&sessions, 0, loss);
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }
}

/// What the predictor did over the corpus: guesses shown, those the next screen did not bear out
/// (a brief flash), and guesses still shown after the frame that echoes their keys that disagree
/// with it (which must never happen).
#[derive(Default)]
struct Guesses {
    shown: usize,
    wrong: usize,
    disagreeing: Vec<String>,
}

/// Replay `recording` with its keys typed into a predicting client, each step's output answered
/// with a frame that echoes every key typed so far.
fn guesses(recording: &Recording, into: &mut Guesses) -> Result<(), String> {
    let size = Size::new(recording.rows, recording.cols);
    let mut server = ServerTerminal::new(recording.rows, recording.cols, SCROLLBACK)
        .map_err(|e| e.to_string())?;
    // The PTY's modes as an interactive program sets them, a line editor's included: keys are
    // echoed by the program, a key at a time.
    server.set_tty(koh::terminal::TtyModes {
        echo: false,
        line: false,
    });
    let mut client = ClientSession::new(size);
    let mut sent = TerminalScreen::default();
    let mut num = FrameNum::BLANK;
    let mut typed = InputSeq::default();
    // A step a second: keys are typed a moment after the screen they are typed at, as a person
    // types them, not inside the client's hold at a fresh prompt.
    let mut now = Instant::now();
    let cell = |screen: &TerminalScreen, row: u16, col: u16| {
        screen
            .screen()
            .cell(row, col)
            .map(|c| c.contents().to_owned())
            .unwrap_or_default()
    };
    for (index, (step, output)) in recording.outputs().enumerate() {
        now = now.checked_add(Duration::from_secs(1)).unwrap_or(now);
        if let Some((rows, cols)) = step.resize {
            server.resize(Size::new(rows, cols));
            client.on_resize(Size::new(rows, cols));
        }
        if !step.keys.is_empty() {
            client.on_input(now, &step.keys);
        }
        while let Some(msg) = client.pop_outgoing() {
            if let ClientMsg::Keys { seq, .. } = msg {
                typed = typed.max(seq);
            }
        }
        let before: Vec<((u16, u16), String)> = client
            .overlay()
            .cells()
            .filter(|(_, c)| !c.covered())
            .map(|(at, c)| (at, c.text().to_owned()))
            .collect();
        server.process(output);
        let screen = server.snapshot();
        let next = num.next();
        client.on_frame(
            now,
            &Frame {
                num: next,
                base: num,
                echo_ack: typed,
                diff: screen.diff_from(&sent),
            },
        );
        num = next;
        sent = screen;
        into.shown = into.shown.saturating_add(before.len());
        into.wrong = into.wrong.saturating_add(
            before
                .iter()
                .filter(|((row, col), glyph)| cell(client.state(), *row, *col) != *glyph)
                .count(),
        );
        for ((row, col), c) in client.overlay().cells() {
            let shown = cell(client.state(), row, col);
            if !c.covered() && shown != c.text() {
                into.disagreeing.push(format!(
                    "{} step {index}: ({row}, {col}) guessed {:?}, the server shows {shown:?}",
                    recording.name,
                    c.text()
                ));
            }
        }
    }
    Ok(())
}

#[test]
fn confirmed_guesses_never_disagree_with_the_server() {
    let corpus = corpus().expect("corpus");
    let mut total = Guesses::default();
    for recording in corpus
        .iter()
        .filter(|r| r.steps.iter().any(|s| !s.keys.is_empty()))
    {
        guesses(recording, &mut total).expect("replay");
    }
    println!(
        "guesses shown {}, not borne out by the next screen {}",
        total.shown, total.wrong
    );
    assert!(total.shown > 0, "the corpus's keys made no guess");
    assert!(
        total.disagreeing.is_empty(),
        "{}",
        total.disagreeing.join("\n")
    );
}

/// What the recording's program read for its keys: each key typed decoded, then encoded as the
/// program asked at that moment, as fux's recorder made the recordings (`record.rs`, `typed`).
fn read_by_the_program(keys: &[u8], screen: &fux_vt::Screen) -> Vec<u8> {
    use fux_vt::keys::decode::{Decoder, Input};
    let mut decoder = Decoder::default();
    let mut inputs = Vec::new();
    decoder.bytes(keys, &mut inputs);
    decoder.timeout(&mut inputs);
    let mut out = Vec::new();
    for input in inputs {
        match input {
            Input::Key(stroke) => screen.encode_key(stroke, &mut out),
            Input::Paste(text) => screen.encode_paste(&text, &mut out),
            Input::PasteTooLong
            | Input::FocusIn
            | Input::FocusOut
            | Input::Mouse(_)
            | Input::Reply(_) => {}
        }
    }
    out
}

/// The corpus's keys, typed on a legacy terminal, through koh: decoded by the client, sent on the
/// wire, encoded by the server for the program in the mode its output set by then. The program
/// gets what fux's recorder gave it: kitty's keys to nvim, helix and the rest that push flags,
/// legacy bytes to the others.
#[test]
fn the_corpus_keys_reach_each_program_as_it_read_them() {
    let corpus = corpus().expect("corpus");
    let mut compared = 0usize;
    let mut kitty = 0usize;
    for recording in &corpus {
        let size = Size::new(recording.rows, recording.cols);
        let mut server =
            ServerTerminal::new(recording.rows, recording.cols, SCROLLBACK).expect("emulator");
        let mut client = ClientSession::new(size);
        let mut wire = ClientDecoder::default();
        let now = Instant::now();
        for (index, (step, output)) in recording.outputs().enumerate() {
            if let Some((rows, cols)) = step.resize {
                server.resize(Size::new(rows, cols));
            }
            if !step.keys.is_empty() {
                client.on_input(now, &step.keys);
                if let Some(deadline) = client.deadline() {
                    client.on_timeout(deadline);
                }
                let mut got = Vec::new();
                while let Some(msg) = client.pop_outgoing() {
                    wire.push(&encode_client(&msg).expect("encodes"));
                    while let Some(msg) = wire.next_msg().expect("decodes") {
                        if let ClientMsg::Keys { events, .. } = msg {
                            server.encode_input(&events, &mut got);
                        }
                    }
                }
                let expected = read_by_the_program(&step.keys, server.live());
                assert_eq!(
                    got,
                    expected,
                    "{} step {index}: keys {:?}",
                    recording.name,
                    String::from_utf8_lossy(&step.keys)
                );
                compared = compared.saturating_add(1);
                if server.live().kitty_keyboard_flags() != 0 {
                    kitty = kitty.saturating_add(1);
                }
            }
            server.process(output);
            let _ = server.take_host_replies();
        }
    }
    println!("{compared} steps' keys compared, {kitty} to a program in the kitty protocol");
    assert!(compared > 100 && kitty > 10, "{compared} {kitty}");
}

/// zellij asks for all 256 palette entries at start-up. Given the user's terminal's colours, the
/// server answers entries 0 to 15 with them and the rest as before (xterm's), and every other
/// reply is unchanged.
#[test]
fn zellij_is_answered_with_the_users_palette() {
    use koh::events::{WireColours, PALETTE};
    let corpus = corpus().expect("corpus");
    let zellij = corpus.iter().find(|r| r.name == "zellij").expect("zellij");
    let replies = |colours: Option<&WireColours>| {
        let mut server =
            ServerTerminal::new(zellij.rows, zellij.cols, SCROLLBACK).expect("emulator");
        if let Some(colours) = colours {
            server.set_colours(colours);
        }
        let mut all = Vec::new();
        for (_, output) in zellij.outputs() {
            server.process(output);
            all.extend(server.take_host_replies());
        }
        String::from_utf8_lossy(&all).into_owned()
    };
    let palette: Vec<Option<[u8; 3]>> = (0..PALETTE)
        .map(|i| Some([u8::try_from(i).unwrap(), 0x11, 0x22]))
        .collect();
    let told = WireColours {
        palette,
        ..WireColours::default()
    };
    let (before, after) = (replies(None), replies(Some(&told)));
    let entries =
        |text: &str| -> Vec<String> { text.split("\x1b]4;").skip(1).map(str::to_owned).collect() };
    let (before, after) = (entries(&before), entries(&after));
    assert_eq!(before.len(), after.len());
    assert!(before.len() >= 256, "{}", before.len());
    let mut changed = 0;
    for (b, a) in before.iter().zip(&after) {
        let index: u16 = b.split(';').next().unwrap().parse().unwrap();
        if index < 16 {
            let expected = format!("{index};rgb:{index:02x}{index:02x}/1111/2222");
            assert!(a.starts_with(&expected), "{a:?} for entry {index}");
            changed += 1;
        } else {
            assert_eq!(a, b, "entry {index}");
        }
    }
    assert!(changed >= 16, "{changed}");
}
