//! Detachable sessions, as tasks.
//!
//! A [`Registry`] task creates, reattaches, caps, lists and ends them, by peer and number: a peer
//! may have several, each numbered server-wide as it starts. Each session task owns its program's
//! PTY and emulator and publishes what the program shows as [`Event`]s, its output filtered
//! ([`crate::stream`]), attached or not; a client that attaches is sent a redraw of the screen as
//! it is, then the events from there. Once the program exited, the session keeps its end until a
//! client was told it, or the TTL runs out.
//!
//! A connection talks to its session through a [`SessionClient`]. Its presence receiver is its
//! attachment, so dropping it detaches; its input reaches the program only while it is the newest
//! attachment and the program runs.

use std::sync::Arc;
use std::time::Duration;

use crate::bounded::Bounded;
use crate::events::InputEvent;
use crate::proto::{Close, InputSeq, MarkText, Shown, TTY_TICK};
use crate::pty::Exit;
use crate::request::{Pick, Presence, RunId, SessionInfo, SessionNum, ShellState, MAX_TITLE};
use crate::stream::{Filter, Marks, Piece, Policy};
use crate::terminal::{Activity, ServerTerminal, Size, TtyModes};
use anyhow::Context;
use iroh::EndpointId;
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio::time::{Instant, MissedTickBehavior};
use tokio_util::sync::CancellationToken;

mod reports;
mod sessions;

use reports::{Probe, Reports};

/// How much input may wait for a session's PTY before a connection must stop reading its stream.
const INPUT_QUEUE: usize = 256;

/// How many asks (text, the end seen, resizes) may wait for a session.
const ASK_QUEUE: usize = 64;

/// How many events a session keeps for its slowest client: past them, that client is sent a
/// redraw instead of what it missed. An [`Shown::Out`] is at most 16 KiB, so this is at most
/// 2 MiB of output a session.
const EVENTS: usize = 128;

/// Most output chunks read at once beyond the first, so a program that never stops writing
/// cannot starve input.
const OUTPUT_CHUNKS_AT_ONCE: usize = 64;

/// How long a program's output must be quiet, after its exit was seen, to count as drained: the
/// last of what it wrote is read by then, so the client is sent it.
const DRAINED: Duration = TTY_TICK;

/// How soon after output the PTY's modes are read again, then twice as long each time until a
/// tick. Output that is no echo of typing waits for that read before it is sent: a password prompt
/// printed just before echo goes off (PAM's order) is never told with echo on, which the client
/// would trust to show what is typed at it.
const TTY_SETTLE: Duration = Duration::from_millis(10);

/// Most bytes of output held for the modes' read: past them it goes at once.
const HELD_MOST: usize = 1 << 20;

/// The longest the output may go on after the exit was seen: a job left in the background writing
/// for ever does not keep the session from ending, while a slow server still reads what an exited
/// program left queued.
const DRAIN_MOST: Duration = Duration::from_secs(5);

/// How long the session waits, once the program's output ended with no exit seen (it closed its
/// terminal and runs on), for the exit before it counts the program hung up.
const ENDING_GRACE: Duration = Duration::from_secs(1);

/// How long a retry of input the PTY did not take waits.
const INPUT_RETRY: Duration = Duration::from_millis(10);

/// How long the program gets to show a keystroke before it counts as echoed.
const ECHO_TIMEOUT: Duration = Duration::from_millis(50);

/// Most inputs awaiting their echo: past them, the newest waits in place of the one before it.
const ECHO_PENDING: usize = 256;

/// Rows of history a client attaching afresh (not redialing) is sent above the screen, into its
/// terminal's scrollback.
pub const ATTACH_HISTORY: usize = 1000;

/// One pending input batch, followed by terminal replies generated while it waits. Client
/// input pauses while this is nonempty. Replies have a separate 64 KiB reserve; overflow
/// drops a whole reply batch and warns once until the queue drains.
#[derive(Default)]
struct PendingInput {
    bytes: Vec<u8>,
    replies: usize,
    overflow_reported: bool,
    /// The input it holds, which counts as written once it is.
    seq: Option<InputSeq>,
}

impl PendingInput {
    fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    fn reply(&mut self, bytes: &[u8]) {
        const REPLY_BUDGET: usize = 64 * 1024;
        if self.replies.saturating_add(bytes.len()) > REPLY_BUDGET {
            if !self.overflow_reported {
                tracing::warn!("PTY reply reserve full; terminal reply batch dropped");
                self.overflow_reported = true;
            }
            return;
        }
        self.bytes.extend_from_slice(bytes);
        self.replies = self.replies.saturating_add(bytes.len());
    }

    /// Write what is pending; once all of it is written, the input it held, if any.
    #[expect(
        clippy::option_option,
        reason = "not written, written with no input, or written with this input"
    )]
    fn flush(
        &mut self,
        write: impl FnOnce(Vec<u8>) -> Result<(), crate::pty::WriteError>,
    ) -> Option<Option<InputSeq>> {
        if self.is_empty() {
            return None;
        }
        match write(std::mem::take(&mut self.bytes)) {
            Ok(()) => Some(std::mem::take(self).seq),
            Err(crate::pty::WriteError::Full(bytes)) => {
                self.bytes = bytes;
                None
            }
            Err(crate::pty::WriteError::Closed(_)) => {
                tracing::warn!("PTY input closed; pending input discarded");
                *self = Self::default();
                None
            }
        }
    }
}

/// Which of the newest attachment's inputs the program has had time to show.
#[derive(Debug, Default)]
struct EchoAck {
    /// Inputs written and not yet promoted, with when, oldest first.
    pending: Bounded<(InputSeq, Instant), ECHO_PENDING>,
}

impl EchoAck {
    /// Input `seq` was written at `now`. Past [`ECHO_PENDING`] waiting, the newest waits in place
    /// of the one before it.
    fn written(&mut self, seq: InputSeq, now: Instant) {
        if let Err(input) = self.pending.push_back((seq, now)) {
            if let Some(last) = self.pending.back_mut() {
                last.0 = input.0;
            }
        }
    }

    /// The newest input that had its time to show by `now`, if one did since last asked.
    fn promote(&mut self, now: Instant) -> Option<InputSeq> {
        let mut promoted = None;
        while let Some(&(seq, at)) = self.pending.front() {
            if now.saturating_duration_since(at) < ECHO_TIMEOUT {
                break;
            }
            promoted = Some(seq);
            self.pending.pop_front();
        }
        promoted
    }

    fn next(&self) -> Option<Instant> {
        let (_, at) = self.pending.front()?;
        at.checked_add(ECHO_TIMEOUT)
    }
}

/// The hosted program: a process on a PTY, its emulator, and the filter its output goes through.
struct PtyHost {
    emu: ServerTerminal,
    pty: crate::pty::Pty,
    filter: Filter,
    /// The attachment and number of the newest resize applied.
    resized: (u64, u32),
}

impl PtyHost {
    /// Start `command` (empty for `$SHELL`) in `home` at `size`, left to `reaper` once closed, a
    /// shell `marks` knows started so that it marks its commands, and only its marks counted; the
    /// host and a receiver of its output. Blocks until the program starts.
    fn spawn(
        command: &[String],
        (size, scrollback_bytes): (Size, usize),
        (home, marks): (&crate::pty::Home, Option<&super::marks::MarksDir>),
        reaper: &crate::pty::Reaper,
    ) -> anyhow::Result<(Self, mpsc::Receiver<Vec<u8>>)> {
        let size = crate::terminal::clamp_dims(size);
        let Size { rows, cols } = size;
        let mut emu = ServerTerminal::new(rows, cols, scrollback_bytes)
            .context("creating the terminal emulator")?;
        let argv = crate::pty::session_argv(command);
        let marked = marks.and_then(|marks| marks.mark(&argv));
        let (argv, env) = marked
            .as_ref()
            .map_or((&argv[..], &[][..]), |m| (&m.argv[..], &m.env[..]));
        let (pty, pty_rx) =
            crate::pty::Pty::spawn(rows, cols, argv, env, "xterm-256color", home, reaper)
                .context("spawning shell")?;
        let nonce = marked.as_ref().map(|m| m.nonce.as_bytes().to_vec());
        emu.require_mark_nonce(nonce.as_deref());
        let filter = Filter::new(Policy {
            marks: nonce.map_or(Marks::All, Marks::Signed),
            clipboard: true,
            links: true,
        });
        Ok((
            Self {
                emu,
                pty,
                filter,
                resized: (0, 0),
            },
            pty_rx,
        ))
    }

    /// The PTY's modes, read now; `None` if they cannot be read.
    fn tty(&self) -> Option<TtyModes> {
        self.pty.tty_modes()
    }

    /// The client's window is now `size` (clamped); whether that changed the size. A program that
    /// asked for in-band resize reports (mode 2048) hears of it on its input, in `pending`.
    fn resize(&mut self, size: Size, pending: &mut PendingInput) -> bool {
        if !self.emu.resize(size) {
            return false;
        }
        let host = crate::terminal::host_size(size);
        if let Err(e) = self.pty.resize(host.rows(), host.cols()) {
            tracing::warn!(error = %e, rows = host.rows(), cols = host.cols(), "pty resize failed");
        }
        if let Some(report) = self.emu.resize_report() {
            pending.reply(&report);
        }
        true
    }

    /// The program's exit, if it has exited: reaped then.
    fn exit(&mut self) -> Option<Exit> {
        self.pty
            .try_wait()
            .map_err(|error| tracing::warn!(%error, "waiting for the session's program failed"))
            .ok()
            .flatten()
    }

    /// Queue what the program gets of `input` from attachment `attach` in `pending`; whether the
    /// size changed. A resize is applied once, whichever way it came first, and never one older.
    fn apply(&mut self, attach: u64, input: ToSession, pending: &mut PendingInput) -> bool {
        match input {
            ToSession::Events { seq, events } => {
                self.emu.encode_input(&events, &mut pending.bytes);
                pending.seq = Some(seq);
            }
            // A program that subscribed to scheme changes (mode 2031) hears of a new one on its
            // input.
            ToSession::Colours(colours) => {
                pending.bytes.extend(self.emu.set_colours(&colours));
            }
            ToSession::Resize(window) if (attach, window.n) > self.resized => {
                self.resized = (attach, window.n);
                return self.resize(window.size, pending);
            }
            ToSession::Resize(_) => {}
        }
        false
    }

    /// What the shell's marks and the last probe say of it.
    fn shell_state(&self, activity: Option<Activity>) -> ShellState {
        let commands = self.emu.live().commands();
        ShellState {
            activity,
            running: commands.running(),
            finished: commands.finished,
            last_status: commands.last_status,
        }
    }
}

/// What a connection hands its session, in the order the client sent it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ToSession {
    /// Decoded input ([`crate::proto::ClientMsg::Keys`]), which the session encodes as its
    /// program asked.
    Events {
        seq: InputSeq,
        events: Vec<InputEvent>,
    },
    /// What the user's terminal said of its colours.
    Colours(crate::events::WireColours),
    /// The client's window, among its input so nothing typed after it overtakes it.
    Resize(Window),
}

/// The client's window, clamped, and the number of the resize that sent it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Window {
    pub(crate) n: u32,
    pub(crate) size: Size,
}

/// What is known of how the program ended, and so when the session counts it ended: its exit once
/// known and its output drained (or [`DRAIN_MOST`] after the exit), or, its output ended with no
/// exit, hung up after a grace. Every input is named, and the time passed in.
#[derive(Debug, Default)]
struct Ending {
    /// The exit, and when it was seen.
    exit: Option<(Exit, Instant)>,
    /// When the output ended: the program and everything it left closed the terminal.
    output_ended: Option<Instant>,
    /// When output was last read.
    last_output: Option<Instant>,
}

impl Ending {
    /// When the program counts as ended, and how, as things stand: never while it writes.
    fn deadline(&self) -> Option<(Instant, Exit)> {
        match (self.exit, self.output_ended) {
            (Some((exit, _)), Some(ended)) => Some((ended, exit)),
            (Some((exit, seen)), None) => {
                let quiet_from = self.last_output.map_or(seen, |last| last.max(seen));
                let drained = quiet_from.checked_add(DRAINED)?;
                Some((drained.min(seen.checked_add(DRAIN_MOST)?), exit))
            }
            (None, Some(ended)) => Some((ended.checked_add(ENDING_GRACE)?, Exit::HungUp)),
            (None, None) => None,
        }
    }

    /// How the program ended, if it counts as ended at `now`.
    fn ended(&self, now: Instant) -> Option<Exit> {
        self.deadline()
            .filter(|(at, _)| now >= *at)
            .map(|(_, exit)| exit)
    }
}

/// Input for the program, from the attachment numbered `attach`.
pub(crate) struct Input {
    pub(crate) attach: u64,
    pub(crate) input: ToSession,
}

/// What a session publishes, in order, to every client attached.
#[derive(Clone, Debug)]
pub enum Event {
    /// What the program shows, shared by every client.
    Show(Arc<Shown>),
    /// The input up to `seq` of attachment `attach` had its time to show.
    Echo { attach: u64, seq: InputSeq },
}

/// What a client is sent from where it begins: the screen as it is, then the events after it.
pub struct Start {
    /// The redraw, the modes and the last report.
    pub shown: Vec<Shown>,
    pub events: broadcast::Receiver<Event>,
}

/// What a connection asks its session beside input: served whatever the program is doing.
enum Ask {
    /// A redraw, and the events after it: for a client that fell behind.
    Redraw(oneshot::Sender<Start>),
    /// A client was told the program's end: once it exited, the session ends.
    Ended,
    /// The window of attachment `attach` is now `size` (clamped): asked beside input, so a
    /// resize never waits behind typing the program has not taken.
    Resize { attach: u64, window: Window },
    /// How the session stands, for a listing.
    Describe(oneshot::Sender<Description>),
    /// The screen's text, or the last command's output if `last`.
    Text {
        last: bool,
        reply: oneshot::Sender<Option<String>>,
    },
}

/// How a session stands, as it says for a listing.
struct Description {
    /// Since when no client is attached, if none is.
    detached: Option<Instant>,
    size: Size,
    title: String,
    exited: Option<u32>,
    state: ShellState,
}

/// What a session publishes of how it stands, for waits: whenever it changes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Status {
    pub state: ShellState,
    pub exited: Option<u32>,
    /// The screen's text holds the text a wait asked for: changed whenever the screen did.
    pub screen: u64,
}

/// Whether [`Registry::attach`] created a fresh session or reattached to a running one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachKind {
    /// A brand-new session was spawned for this peer.
    Created,
    /// Reattached; `detached_for` is how long it had no client, `None` if it had one.
    Reattached { detached_for: Option<Duration> },
}

/// What an attach gets: a session and where its client begins, or why not
/// ([`Close::AtCapacity`], [`Close::CouldNotStart`], [`Close::NoSuchSession`]).
type Attached = Result<(SessionClient, Start, AttachKind), Close>;

/// A connection's handle to its session: send input, ask, and detach on drop.
pub struct SessionClient {
    /// Which session it is.
    session: SessionNum,
    /// The attachment itself: the session counts its clients by these receivers, so this is
    /// never cloned, and none is made but for a client.
    _presence: watch::Receiver<()>,
    /// Where input goes, as attachment number `attach`: the session takes only the newest's.
    pub(crate) input: mpsc::Sender<Input>,
    pub(crate) attach: u64,
    asks: mpsc::Sender<Ask>,
}

impl SessionClient {
    /// Which session it is attached to.
    pub const fn session(&self) -> SessionNum {
        self.session
    }

    /// Its attachment's number: the session's events for its input carry it.
    pub const fn attachment(&self) -> u64 {
        self.attach
    }

    /// A redraw and the events after it, for a client that fell behind; `None` if the session
    /// ended.
    pub async fn redraw(&self) -> Option<Start> {
        let (reply, answer) = oneshot::channel();
        self.asks.send(Ask::Redraw(reply)).await.ok()?;
        answer.await.ok()
    }

    /// The client's window is now `window` (clamped); `false` if the session cannot take it yet.
    pub(crate) fn resize(&self, window: Window) -> bool {
        let attach = self.attach;
        self.asks.try_send(Ask::Resize { attach, window }).is_ok()
    }

    /// The client was told the program's end: the session, its program exited, may end.
    pub async fn ended(&self) {
        let _ = self.asks.send(Ask::Ended).await;
    }
}

// --- the session task -------------------------------------------------------------------------

/// A connection attaches to a session at a window size, with history above the redraw if it
/// attaches afresh.
struct Attach {
    size: Size,
    history: usize,
    /// What a new session runs in place of the spec's command.
    program: Option<Arc<[String]>>,
    reply: oneshot::Sender<Attached>,
}

/// How many attaches may wait for one session; past them, one is refused as at capacity.
const CONTROL_QUEUE: usize = 8;

/// A session's handles, kept by the registry.
pub(super) struct Handles {
    control: mpsc::Sender<Attach>,
    asks: mpsc::Sender<Ask>,
    status: watch::Receiver<Status>,
}

/// Start session `session` for `spec`, its program left to `reaper` once closed, answering `first`
/// once it started: its handles, and the task that runs it.
fn start(
    session: SessionNum,
    spec: &SessionSpec,
    reaper: &crate::pty::Reaper,
    first: Attach,
) -> (
    Handles,
    impl std::future::Future<Output = ()> + Send + 'static,
) {
    let (control, control_rx) = mpsc::channel(CONTROL_QUEUE);
    let (asks, asks_rx) = mpsc::channel(ASK_QUEUE);
    let (status_tx, status) = watch::channel(Status::default());
    let asked = asks.clone();
    let command = first
        .program
        .clone()
        .unwrap_or_else(|| Arc::clone(&spec.command));
    let (scrollback_bytes, ttl, home) = (spec.scrollback_bytes, spec.ttl, spec.home.clone());
    let marks = spec.marks.clone();
    let reaper = reaper.clone();
    let task = async move {
        let size = first.size;
        // Forking and the program's exec block, and must hold up no other session.
        let spawned = tokio::task::spawn_blocking(move || {
            PtyHost::spawn(
                &command,
                (size, scrollback_bytes),
                (&home, marks.as_deref()),
                &reaper,
            )
        })
        .await;
        let (host, pty_rx) = match spawned.map_err(anyhow::Error::from).and_then(|s| s) {
            Ok(spawned) => spawned,
            Err(e) => {
                tracing::error!(error = %e, "spawning a session failed");
                let _ = first.reply.send(Err(Close::CouldNotStart));
                return;
            }
        };
        let (events, _) = broadcast::channel(EVENTS);
        let (presence, _) = watch::channel(());
        let (input, input_rx) = mpsc::channel(INPUT_QUEUE);
        let mut session = Session {
            num: session,
            host,
            events,
            presence,
            status: status_tx,
            input,
            asks,
            attaches: 0,
            reports: Reports::default(),
            tty: None,
            title: String::new(),
            bells: 0,
            echo: EchoAck::default(),
            written: InputSeq::default(),
            screen_changes: 0,
            exited: None,
        };
        // A requester already gone drops its client, which the session sees as a detach.
        let (client, start) = session.client(first.size, first.history);
        let _ = first.reply.send(Ok((client, start, AttachKind::Created)));
        session
            .run(pty_rx, control_rx, input_rx, asks_rx, ttl)
            .await;
    };
    (
        Handles {
            control,
            asks: asked,
            status,
        },
        task,
    )
}

/// Wait until `deadline`, or forever if there is none.
async fn until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

/// A running session: its program, and what its clients hold of it.
struct Session {
    num: SessionNum,
    host: PtyHost,
    /// What the program shows, for every client attached.
    events: broadcast::Sender<Event>,
    /// Its clients are this sender's receivers: no other receiver may exist.
    presence: watch::Sender<()>,
    status: watch::Sender<Status>,
    input: mpsc::Sender<Input>,
    asks: mpsc::Sender<Ask>,
    /// How many attaches there were: the newest's number, whose input alone is taken.
    attaches: u64,
    /// What it reported of what the program is doing.
    reports: Reports,
    /// The PTY's modes as last told.
    tty: Option<TtyModes>,
    /// The title as last told.
    title: String,
    /// The bells as last told.
    bells: u64,
    /// The newest attachment's inputs awaiting their echo.
    echo: EchoAck,
    /// The newest attachment's newest input written to the program: what a report follows.
    written: InputSeq,
    /// How often the screen changed: a wait for text looks again at each.
    screen_changes: u64,
    /// The program's status, once it exited: a client attaching then is told it.
    exited: Option<u32>,
}

impl Session {
    /// A new attachment, the newest, at `size`, with `history` rows above its redraw.
    fn client(&mut self, size: Size, history: usize) -> (SessionClient, Start) {
        self.attaches = self.attaches.saturating_add(1);
        self.echo = EchoAck::default();
        self.written = InputSeq::default();
        let mut pending = PendingInput::default();
        let window = Window { n: 0, size };
        if self
            .host
            .apply(self.attaches, ToSession::Resize(window), &mut pending)
        {
            self.reports.owe();
        }
        // A resize report owed the program.
        let _ = pending.flush(|bytes| self.host.pty.write(bytes));
        let client = SessionClient {
            session: self.num,
            _presence: self.presence.subscribe(),
            input: self.input.clone(),
            attach: self.attaches,
            asks: self.asks.clone(),
        };
        (client, self.start(history))
    }

    /// Where a client begins: the screen, the modes, the last report, then the events after.
    fn start(&self, history: usize) -> Start {
        let emu = &self.host.emu;
        let mut shown: Vec<Shown> = crate::terminal::redraw(emu.live(), emu.title(), history)
            .into_iter()
            .flat_map(redrawn)
            .collect();
        if let Some(tty) = self.tty {
            shown.push(Shown::Tty(tty));
        }
        shown.push(Shown::Title(emu.title().to_owned()));
        shown.push(Shown::Bell(emu.bell_count()));
        if let Some(report) = self.reports.last() {
            shown.push(Shown::Report {
                activity: report.activity,
                input: self.written,
            });
        }
        if let Some(code) = self.exited {
            shown.push(Shown::Exit(code));
        }
        Start {
            shown,
            events: self.events.subscribe(),
        }
    }

    /// Tell every client `shown`.
    fn show(&self, shown: Shown) {
        let _ = self.events.send(Event::Show(Arc::new(shown)));
    }

    /// Publish how the session stands, if it changed.
    fn publish_status(&self, exited: Option<u32>) {
        let status = Status {
            state: self
                .host
                .shell_state(self.reports.last().map(|r| r.activity)),
            exited,
            screen: self.screen_changes,
        };
        self.status.send_if_modified(|now| {
            let changed = *now != status;
            *now = status;
            changed
        });
    }

    /// Read the PTY's modes and tell them if they changed.
    fn refresh_tty(&mut self) {
        let tty = self.host.tty();
        if tty.is_some() && tty != self.tty {
            self.tty = tty;
            if let Some(tty) = tty {
                self.show(Shown::Tty(tty));
            }
        }
    }

    /// Probe what the program is doing at `now`, for `why`, input last written to it at `typed`
    /// and the screen changed since if `answered`; told if a report is due.
    fn probe(&mut self, now: Instant, why: Probe, (typed, answered): (Option<Instant>, bool)) {
        let since_key = typed.map_or(Duration::MAX, |at| now.saturating_duration_since(at));
        let prompt = self.host.emu.live().commands().prompt;
        let activity = self.host.pty.activity(since_key, answered, prompt);
        if let Some(report) = self.reports.probed(now, why, activity) {
            self.show(Shown::Report {
                activity: report.activity,
                input: self.written,
            });
        }
    }

    /// Probe for a report as polled, after what is `held` is told (with the modes read first, as
    /// its settling would): a report never goes before output the program wrote before it.
    fn report(&mut self, held: &mut Vec<Shown>, typed: (Option<Instant>, bool)) {
        if !held.is_empty() {
            self.refresh_tty();
            self.release(held);
        }
        self.probe(Instant::now(), Probe::Poll, typed);
    }

    /// Feed `chunk` to the emulator and the filter; what passes goes into `held`.
    fn output(&mut self, chunk: &[u8], held: &mut Vec<Shown>) {
        self.host.emu.process(chunk);
        let mut pieces = Vec::new();
        self.host
            .filter
            .feed(chunk, &mut |piece| pieces.push(piece));
        held.extend(pieces.into_iter().filter_map(shown_of));
    }

    /// Tell what was held, after the side channels the output changed: the output in pieces as
    /// large as a message holds, not a read's.
    fn release(&mut self, held: &mut Vec<Shown>) {
        coalesce(held);
        let title = self.host.emu.title();
        if title != self.title {
            self.title = title.to_owned();
            self.show(Shown::Title(self.title.clone()));
        }
        for shown in held.drain(..) {
            self.show(shown);
        }
        let bells = self.host.emu.bell_count();
        if bells != self.bells {
            self.bells = bells;
            self.show(Shown::Bell(bells));
        }
    }

    /// Run until the program exited and a client was told its end, the session is detached for
    /// the whole `ttl`, or the registry ends it.
    async fn run(
        mut self,
        mut pty_rx: mpsc::Receiver<Vec<u8>>,
        mut control: mpsc::Receiver<Attach>,
        mut input_rx: mpsc::Receiver<Input>,
        mut asks_rx: mpsc::Receiver<Ask>,
        ttl: Duration,
    ) {
        // Since when no client is attached; `None` while one is, or left unseen (the `closed` arm
        // or an attach settles it).
        let mut detached: Option<Instant> = None;
        let mut pending = PendingInput::default();
        // Looked for at every tick and at the output's end, never waited on: a program that closed
        // its terminal may run on, and a job it left in the background may hold its terminal open
        // after it exited.
        let mut ending = Ending::default();
        let mut exited: Option<u32> = None;
        let mut tty_tick = tokio::time::interval(TTY_TICK);
        tty_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        // The next read of the PTY's modes after output, and the wait before the one after it.
        let mut settle: Option<(Instant, Duration)> = None;
        // When typed input last reached the program.
        let mut typed_at: Option<Instant> = None;
        // Output waiting for the modes' read, and its bytes.
        let mut held: Vec<Shown> = Vec::new();
        // Whether the program wrote after the input that reached it last, which the probe asks.
        let mut answered = false;
        // While a client is attached, what the program is doing is probed for a change.
        let mut poll = tokio::time::interval(reports::POLL);
        poll.set_missed_tick_behavior(MissedTickBehavior::Delay);
        self.refresh_tty();

        loop {
            if let Some(exit) = ending.ended(Instant::now()).filter(|_| exited.is_none()) {
                // Whatever is held goes first, then the end. Input goes nowhere from now on.
                self.release(&mut held);
                let code = exit.code();
                self.show(Shown::Exit(code));
                exited = Some(code);
                self.exited = exited;
                pending = PendingInput::default();
                // Its output is read no more: a job left writing stops the reader, not wakes it.
                pty_rx.close();
                self.publish_status(exited);
            }
            if exited.is_none() {
                if let Some(Some(seq)) = pending.flush(|bytes| self.host.pty.write(bytes)) {
                    {
                        let now = Instant::now();
                        typed_at = Some(now);
                        answered = false;
                        self.reports.owe();
                        self.echo.written(seq, now);
                        self.written = seq;
                    }
                }
            }
            let reading = exited.is_none() && ending.output_ended.is_none();
            let held_bytes: usize = held
                .iter()
                .map(|s| if let Shown::Out(b) = s { b.len() } else { 0 })
                .sum();

            tokio::select! {
                chunk = pty_rx.recv(), if reading => {
                    let now = Instant::now();
                    if let Some(chunk) = chunk {
                        ending.last_output = Some(now);
                        let marks = self.host.emu.live().commands();
                        self.output(&chunk, &mut held);
                        for _ in 0..OUTPUT_CHUNKS_AT_ONCE {
                            let Ok(more) = pty_rx.try_recv() else { break };
                            self.output(&more, &mut held);
                        }
                        answered = true;
                        self.screen_changes = self.screen_changes.wrapping_add(1);
                        // Query answers go to the program, not the screen.
                        pending.reply(&self.host.emu.take_host_replies());
                        let echo = typed_at.is_some_and(|at| now.saturating_duration_since(at) < TTY_SETTLE);
                        let marked = self.host.emu.live().commands() != marks;
                        if echo || marked || held_bytes > HELD_MOST {
                            // An echo, or a mark (a prompt's modes are read when it is drawn):
                            // the modes now, then the output.
                            self.refresh_tty();
                            self.release(&mut held);
                            settle = now.checked_add(TTY_SETTLE).map(|at| (at, TTY_SETTLE));
                        } else if settle.is_none() {
                            settle = now.checked_add(TTY_SETTLE).map(|at| (at, TTY_SETTLE));
                        }
                        // The shell marked a command's start or end: a report made after it.
                        if marked {
                            self.probe(now, Probe::Marked, (typed_at, answered));
                        }
                        self.publish_status(exited);
                    } else {
                        ending.output_ended = Some(now);
                        ending.exit = ending.exit.or_else(|| self.host.exit().map(|e| (e, now)));
                    }
                },
                () = until(ending.deadline().map(|(at, _)| at)), if exited.is_none() => {}
                () = until(settle.map(|(at, _)| at)), if exited.is_none() => {
                    let wait = settle.map_or(TTY_TICK, |(_, wait)| wait.saturating_mul(2));
                    settle = Instant::now()
                        .checked_add(wait)
                        .filter(|_| wait < TTY_TICK)
                        .map(|at| (at, wait));
                    self.refresh_tty();
                    self.release(&mut held);
                }
                () = until(self.echo.next()) => {
                    if let Some(seq) = self.echo.promote(Instant::now()) {
                        // What the program wrote in that time goes before.
                        self.release(&mut held);
                        let _ = self.events.send(Event::Echo { attach: self.attaches, seq });
                    }
                }
                // The session holds a sender, so this never ends. Taken while the program cannot,
                // too, and dropped: an old attachment's, or any once the program exited.
                Some(Input { attach, input }) = input_rx.recv(), if pending.is_empty() || exited.is_some() => {
                    if attach == self.attaches && exited.is_none() && self.host.apply(attach, input, &mut pending) {
                        // Resized: a report follows.
                        self.reports.owe();
                        self.screen_changes = self.screen_changes.wrapping_add(1);
                    }
                },
                Some(ask) = asks_rx.recv() => match ask {
                    Ask::Redraw(reply) => {
                        // What is held goes first: the redraw shows it, and the events after it
                        // must not.
                        self.release(&mut held);
                        let _ = reply.send(self.start(0));
                    }
                    Ask::Ended if exited.is_some() => break,
                    Ask::Ended => {}
                    Ask::Resize { attach, window } => {
                        let input = ToSession::Resize(window);
                        if attach == self.attaches && exited.is_none() && self.host.apply(attach, input, &mut pending) {
                            self.reports.owe();
                            self.screen_changes = self.screen_changes.wrapping_add(1);
                        }
                    }
                    Ask::Describe(reply) => {
                        // Squared with the clients as an attach squares it.
                        if detached.is_none() && self.presence.receiver_count() == 0 {
                            detached = Some(Instant::now());
                        }
                        let size = self.host.emu.live().size();
                        let _ = reply.send(Description {
                            detached,
                            size: Size::new(size.rows(), size.cols()),
                            title: self.host.emu.title().chars().take(MAX_TITLE).collect(),
                            exited,
                            state: self.host.shell_state(self.reports.last().map(|r| r.activity)),
                        });
                    }
                    Ask::Text { last, reply } => {
                        let max = crate::request::MAX_OUTPUT.saturating_sub(1024);
                        let text = if last {
                            self.host.emu.last_output(max)
                        } else {
                            Some(self.host.emu.screen_text(max))
                        };
                        let _ = reply.send(text);
                    }
                },
                msg = control.recv() => match msg {
                    Some(Attach { size, history, reply, .. }) => {
                        // The one place the detach is squared with the clients: the last may have
                        // left unseen by the arm below, and it is dated before this attach.
                        if detached.is_none() && self.presence.receiver_count() == 0 {
                            detached = Some(Instant::now());
                        }
                        let detached_for = detached.map(|since| since.elapsed());
                        self.release(&mut held);
                        let (client, start) = self.client(size, history);
                        // A connection already gone drops its client: the session stays detached
                        // since when it was, so an attach that never arrives does not renew its
                        // TTL.
                        if reply.send(Ok((client, start, AttachKind::Reattached { detached_for }))).is_ok() {
                            detached = None;
                        }
                    }
                    // The registry ended this session: revoked, or the server is shutting down.
                    None => break,
                },
                () = self.presence.closed(), if detached.is_none() => {
                    detached = Some(Instant::now());
                }
                () = tokio::time::sleep(INPUT_RETRY), if !pending.is_empty() && exited.is_none() => {}
                // A program may turn echo off without writing anything (a password prompt printed
                // first): the client hears of it within a tick.
                _ = tty_tick.tick(), if exited.is_none() => {
                    let now = Instant::now();
                    ending.exit = ending.exit.or_else(|| self.host.exit().map(|e| (e, now)));
                    if detached.is_none() {
                        self.refresh_tty();
                    }
                }
                // What the program is doing: the report owed, and a change while a client sees it.
                // Output it wrote before goes first: none read and waiting (the report stays owed
                // until that is taken), then what is held for the modes.
                () = until(self.reports.due(Instant::now())), if exited.is_none() && (pty_rx.is_empty() || !reading) => {
                    self.report(&mut held, (typed_at, answered));
                    self.publish_status(exited);
                }
                _ = poll.tick(), if exited.is_none() && self.presence.receiver_count() > 0 => {
                    if pty_rx.is_empty() || !reading {
                        self.report(&mut held, (typed_at, answered));
                        self.publish_status(exited);
                    }
                }
                // Detached for the whole TTL.
                () = until(detached.and_then(|since| since.checked_add(ttl))) => break,
            }
        }

        // Ended: the registry sees the closed control channel, clients their closed events.
        // The teardown is awaited, so the registry's shutdown waits for every program's hang-up.
        drop((control, input_rx, asks_rx));
        let Self { host, .. } = self;
        let _ = tokio::task::spawn_blocking(move || host.pty.close()).await;
    }
}

/// Join the output in `held` into as few messages as hold it, in order.
fn coalesce(held: &mut Vec<Shown>) {
    let mut joined: Vec<Shown> = Vec::with_capacity(held.len());
    for shown in held.drain(..) {
        match (joined.last_mut(), shown) {
            (Some(Shown::Out(last)), Shown::Out(more))
                if last.len().saturating_add(more.len()) <= crate::stream::MAX_OUT =>
            {
                last.extend_from_slice(&more);
            }
            (_, shown) => joined.push(shown),
        }
    }
    *held = joined;
}

/// A redraw's piece as the wire carries it: output in messages of at most
/// [`MAX_OUT`](crate::stream::MAX_OUT) bytes, each ending on a whole character.
fn redrawn(piece: Piece) -> Vec<Shown> {
    let Piece::Out(bytes) = piece else {
        return shown_of(piece).into_iter().collect();
    };
    let mut out = Vec::new();
    let mut rest = bytes.as_slice();
    while !rest.is_empty() {
        let mut at = rest.len().min(crate::stream::MAX_OUT);
        // Back to the start of a character: never inside one.
        while at < rest.len() && rest.get(at).is_some_and(|b| b & 0xc0 == 0x80) {
            at = at.saturating_sub(1);
        }
        let (head, tail) = rest.split_at(at.max(1));
        out.push(Shown::Out(head.to_vec()));
        rest = tail;
    }
    out
}

/// A filter's piece as the wire carries it; a mark no terminal reads is dropped.
fn shown_of(piece: Piece) -> Option<Shown> {
    match piece {
        Piece::Out(bytes) => Some(Shown::Out(bytes)),
        Piece::Mark(mark) => MarkText::new(mark).map(Shown::Mark),
    }
}

// --- the registry -----------------------------------------------------------------------------

/// What the registry is asked.
enum Request {
    /// Attach `peer` to the session `pick` names, answered on `reply`.
    Attach {
        peer: EndpointId,
        pick: Pick,
        attach: Attach,
    },
    /// `peer`'s sessions, to ask how each stands.
    List {
        peer: EndpointId,
        reply: oneshot::Sender<Vec<sessions::Listed>>,
    },
    /// End `peer`'s sessions, if it has any.
    End(EndpointId),
}

/// A handle to the registry task: cheap to clone, one per accept loop.
#[derive(Clone)]
pub struct Registry {
    tx: mpsc::Sender<Request>,
    shutdown: CancellationToken,
    /// What every session's program is left to once closed.
    reaper: crate::pty::Reaper,
    /// This run of the server.
    run: RunId,
}

/// What the registry hosts, and the session TTL.
pub struct SessionSpec {
    pub command: Arc<[String]>,
    pub scrollback_bytes: usize,
    /// Most live sessions, all peers' together.
    pub max_sessions: usize,
    pub ttl: Duration,
    /// The home each session's program gets.
    pub home: crate::pty::Home,
    /// Where the startup files that mark a shell's commands go, if shells are marked.
    pub marks: Option<Arc<super::marks::MarksDir>>,
}

/// How often an attach is tried: one that reached a session as it ended is tried again.
const ATTACH_TRIES: usize = 3;

/// How long a listing waits for the sessions to say how they stand.
const DESCRIBE_WAIT: Duration = Duration::from_secs(2);

/// One of the peer's sessions, found for a question about it.
pub struct Found {
    asks: mpsc::Sender<Ask>,
    status: watch::Receiver<Status>,
}

impl Found {
    /// The screen's text, or the last command's output; `None` if the session ended, or the
    /// output is gone.
    pub async fn text(&self, last: bool) -> Option<String> {
        let (reply, answer) = oneshot::channel();
        self.asks.send(Ask::Text { last, reply }).await.ok()?;
        answer.await.ok().flatten()
    }

    /// How the session stands, as it changes: ended once the session does.
    pub fn status(&self) -> watch::Receiver<Status> {
        self.status.clone()
    }
}

impl Registry {
    /// Spawn the registry task, attaching only the peers `allows` allows when it takes their
    /// attach, and the reaper its sessions' programs are left to: failing to start that fails
    /// here, before any session.
    pub fn spawn(
        spec: SessionSpec,
        allows: impl Fn(&EndpointId) -> bool + Send + 'static,
    ) -> std::io::Result<Self> {
        let reaper = crate::pty::Reaper::start()?;
        let run = RunId::random()?;
        let (tx, rx) = mpsc::channel(64);
        let shutdown = CancellationToken::new();
        #[expect(clippy::disallowed_methods, reason = "one registry a server")]
        tokio::spawn(registry_task(
            sessions::Sessions::new(spec, run, reaper.clone(), Box::new(allows)),
            rx,
            shutdown.clone(),
        ));
        Ok(Self {
            tx,
            shutdown,
            reaper,
            run,
        })
    }

    /// This run of the server, which a client's redial names with the session it was on.
    pub const fn run(&self) -> RunId {
        self.run
    }

    /// What every session's program, and every command `koh exec` runs, is left to once closed.
    pub fn reaper(&self) -> crate::pty::Reaper {
        self.reaper.clone()
    }

    /// Attach `peer` to the session `pick` names, at window `size`: its latest (or a new one if it
    /// has none), a new one, or one by number, which must be the peer's; with a `program`, a new
    /// one running it. A client that attaches afresh (not redialing) is sent [`ATTACH_HISTORY`]
    /// rows of history above the screen.
    pub async fn attach(
        &self,
        peer: EndpointId,
        pick: Pick,
        size: Size,
        program: Option<Arc<[String]>>,
    ) -> Attached {
        let history = if matches!(pick, Pick::Resume(_)) {
            0
        } else {
            ATTACH_HISTORY
        };
        for _ in 0..ATTACH_TRIES {
            let (reply, rx) = oneshot::channel();
            let attach = Attach {
                size,
                history,
                program: program.clone(),
                reply,
            };
            self.tx
                .send(Request::Attach { peer, pick, attach })
                .await
                .map_err(|_closed| Close::CouldNotStart)?;
            // Unanswered: the session ended as it got the attach, and the registry now knows.
            if let Ok(attached) = rx.await {
                return attached;
            }
        }
        Err(Close::CouldNotStart)
    }

    /// `peer`'s session `session`, if it has one by that number.
    pub async fn find(&self, peer: EndpointId, session: SessionNum) -> Option<Found> {
        let (reply, rx) = oneshot::channel();
        self.tx.send(Request::List { peer, reply }).await.ok()?;
        rx.await
            .ok()?
            .into_iter()
            .find(|listed| listed.session == session)
            .map(|listed| Found {
                asks: listed.asks,
                status: listed.status,
            })
    }

    /// `peer`'s sessions, oldest first, each as it says it stands; one that does not say within
    /// [`DESCRIBE_WAIT`] (it is starting, or ending) is left out.
    pub async fn sessions(&self, peer: EndpointId) -> Vec<SessionInfo> {
        let (reply, rx) = oneshot::channel();
        if self.tx.send(Request::List { peer, reply }).await.is_err() {
            return Vec::new();
        }
        let listed = rx.await.unwrap_or_default();
        let deadline = Instant::now().checked_add(DESCRIBE_WAIT);
        let mut infos = Vec::with_capacity(listed.len());
        for sessions::Listed {
            session,
            started,
            asks,
            ..
        } in listed
        {
            let (tx, rx) = oneshot::channel();
            let (Some(deadline), Ok(())) = (deadline, asks.try_send(Ask::Describe(tx))) else {
                continue;
            };
            let Ok(Ok(described)) = tokio::time::timeout_at(deadline, rx).await else {
                continue;
            };
            let now = Instant::now();
            let secs = |since: Instant| now.saturating_duration_since(since).as_secs();
            infos.push(SessionInfo {
                session,
                age_secs: secs(started),
                presence: described.detached.map_or(Presence::Attached, |since| {
                    Presence::Detached { secs: secs(since) }
                }),
                size: described.size,
                title: described.title,
                exited: described.exited,
                state: described.state,
            });
        }
        infos
    }

    /// End `peer`'s sessions, their programs hung up: the peer may no longer connect.
    pub async fn end(&self, peer: EndpointId) {
        let _ = self.tx.send(Request::End(peer)).await;
    }

    /// Stop the registry and every session, and wait for them to end and their programs to be
    /// reaped, each killed once its grace is over.
    pub async fn shutdown(self) {
        self.shutdown.cancel();
        self.tx.closed().await;
        let reaper = self.reaper;
        let _ = tokio::task::spawn_blocking(move || reaper.drain()).await;
    }
}

/// Route attaches to sessions; it never waits on one, so a session starting or ending holds up no
/// other peer.
async fn registry_task(
    mut sessions: sessions::Sessions,
    mut rx: mpsc::Receiver<Request>,
    shutdown: CancellationToken,
) {
    loop {
        let request = tokio::select! {
            // A shutdown starts no session for a request still queued.
            biased;
            () = shutdown.cancelled() => break,
            () = sessions.ended() => continue,
            msg = rx.recv() => match msg {
                Some(msg) => msg,
                None => break,
            },
        };
        match request {
            Request::Attach { peer, pick, attach } => sessions.attach(peer, pick, attach),
            Request::List { peer, reply } => drop(reply.send(sessions.list(peer))),
            Request::End(peer) => sessions.end(peer),
        }
    }
    // `rx` drops only once every session has ended, which `Registry::shutdown` waits for.
    sessions.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::{
        EchoAck, Ending, Exit, InputSeq, PendingInput, DRAINED, DRAIN_MOST, ECHO_TIMEOUT,
        ENDING_GRACE,
    };
    use tokio::time::Instant;

    #[test]
    fn the_program_ends_once_its_exit_is_known_and_its_output_drained() {
        let t0 = Instant::now();
        let ms = |n| t0 + std::time::Duration::from_millis(n);
        // Exited with megabytes still to read: not ended while they come.
        let mut e = Ending {
            exit: Some((Exit::Status(3), t0)),
            ..Ending::default()
        };
        for at in [50, 140, 230] {
            e.last_output = Some(ms(at));
            assert_eq!(e.ended(ms(at) + DRAINED / 2), None, "still writing at {at}");
        }
        assert_eq!(e.ended(ms(230) + DRAINED), Some(Exit::Status(3)));
        // A job left writing in the background holds it only so long.
        e.last_output = Some(t0 + DRAIN_MOST);
        assert_eq!(e.ended(t0 + DRAIN_MOST), Some(Exit::Status(3)));
        // Its output ended too: at once.
        e.output_ended = Some(ms(240));
        assert_eq!(e.ended(ms(240)), Some(Exit::Status(3)));
        // It closed its terminal and runs on: hung up after the grace, unless its exit is seen.
        let mut e = Ending {
            output_ended: Some(t0),
            ..Ending::default()
        };
        assert_eq!(e.ended(t0 + ENDING_GRACE / 2), None);
        assert_eq!(e.ended(t0 + ENDING_GRACE), Some(Exit::HungUp));
        e.exit = Some((Exit::Status(0), ms(10)));
        assert_eq!(e.ended(ms(10)), Some(Exit::Status(0)));
    }

    #[test]
    fn replies_wait_behind_input_and_overflow_is_bounded() {
        let mut pending = PendingInput {
            bytes: b"typed".to_vec(),
            seq: Some(InputSeq(4)),
            ..PendingInput::default()
        };
        assert_eq!(
            pending.flush(|bytes| Err(crate::pty::WriteError::Full(bytes))),
            None
        );
        pending.reply(b"\x1b[1;1R");
        pending.reply(b"\x1b[48;24;80;0;0t");
        let expected = pending.bytes.clone();
        for _ in 0..3 {
            pending.reply(&vec![0; 64 * 1024]);
        }
        assert_eq!(
            pending.bytes, expected,
            "overflow discards whole reply batches"
        );
        assert!(pending.overflow_reported);
        let written = pending.flush(|bytes| {
            assert_eq!(bytes, b"typed\x1b[1;1R\x1b[48;24;80;0;0t");
            Ok(())
        });
        assert_eq!(
            written,
            Some(Some(InputSeq(4))),
            "the input counts as written"
        );
        assert!(pending.is_empty());
        assert!(!pending.overflow_reported);
        pending.reply(b"next");
        assert_eq!(
            pending.flush(|bytes| Err(crate::pty::WriteError::Closed(bytes))),
            None
        );
        assert!(
            pending.is_empty(),
            "closed writers do not retain pending input"
        );
    }

    #[test]
    fn an_input_counts_as_echoed_once_it_had_its_time_and_a_flood_keeps_the_newest() {
        let t0 = Instant::now();
        let mut echo = EchoAck::default();
        assert_eq!(echo.next(), None);
        echo.written(InputSeq(1), t0);
        echo.written(InputSeq(2), t0 + ECHO_TIMEOUT / 2);
        assert_eq!(echo.promote(t0 + ECHO_TIMEOUT / 4), None);
        assert_eq!(echo.promote(t0 + ECHO_TIMEOUT), Some(InputSeq(1)));
        assert_eq!(echo.next(), Some(t0 + ECHO_TIMEOUT / 2 + ECHO_TIMEOUT));
        for n in 3..1000 {
            echo.written(InputSeq(n), t0 + ECHO_TIMEOUT);
        }
        assert_eq!(echo.promote(t0 + ECHO_TIMEOUT * 3), Some(InputSeq(999)));
    }
}
