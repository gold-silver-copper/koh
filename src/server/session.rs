//! Detachable sessions, as tasks.
//!
//! A [`Registry`] task creates, reattaches, caps and ends them, one per peer. Each session task
//! owns its program's PTY and emulator and publishes every screen on a `watch` channel, attached
//! or not, so a client that reconnects finds the live screen: or, once the program exited, its
//! final screen and status, kept until a client acknowledges it or the TTL runs out.
//!
//! A connection talks to its session through a [`SessionClient`]. Its screen receiver is its
//! attachment, so dropping it detaches; its input reaches the program only while it is the newest
//! attachment and the program runs; its history requests take a path of their own, which the
//! session serves whatever its input or its program is doing.

use std::sync::Arc;
use std::time::Duration;

use crate::proto::Close;
use crate::pty::Exit;
use crate::terminal::{
    FrameHold, HistoryReply, HistoryRequest, ServerTerminal, Size, TerminalScreen, DEFAULT_SIZE,
};
use anyhow::Context;
use iroh::EndpointId;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::{Instant, MissedTickBehavior};
use tokio_util::sync::CancellationToken;

mod sessions;

// How often a session reads its PTY's modes when nothing else made it: a password prompt that
// turned echo off after printing is known to the client within this (the wire's contract).
use crate::proto::TTY_TICK;

/// How much input may wait for a session's PTY before a connection must stop reading its stream.
const INPUT_QUEUE: usize = 256;

/// How many asks (history, the end seen) may wait for a session; past them, a history request is
/// answered with no rows.
const ASK_QUEUE: usize = 64;

/// Most output chunks taken into one snapshot beyond the first: one snapshot per 8 KiB read had a
/// chatty program allocate gigabytes a second at the largest size. Bounded, so a program that never
/// stops writing cannot starve input.
const OUTPUT_CHUNKS_PER_SNAPSHOT: usize = 64;

/// How long a program's output must be quiet, after its exit was seen, to count as drained: the
/// last of what it wrote is read by then, so the final screen shows it.
const DRAINED: Duration = TTY_TICK;

/// How soon after output the PTY's modes are read again, then twice as long each time until a
/// tick: a password prompt printed before echo goes off (PAM's order) is told without echo within
/// moments of the prompt, not a tick later, while the client may still trust the echo it shows.
const TTY_SETTLE: Duration = Duration::from_millis(5);

/// The longest the output may go on after the exit was seen: a job left in the background writing
/// for ever does not keep the session from ending, while a slow server still reads what an exited
/// program left queued.
const DRAIN_MOST: Duration = Duration::from_secs(5);

/// How long the session waits, once the program's output ended with no exit seen (it closed its
/// terminal and runs on), for the exit before it counts the program hung up.
const ENDING_GRACE: Duration = Duration::from_secs(1);

/// How long a retry of input the PTY did not take waits.
const INPUT_RETRY: Duration = Duration::from_millis(10);

/// One pending input batch, followed by terminal replies generated while it waits. Client
/// input pauses while this is nonempty. Replies have a separate 64 KiB reserve; overflow
/// drops a whole reply batch and warns once until the queue drains.
#[derive(Default)]
struct PendingInput {
    bytes: Vec<u8>,
    replies: usize,
    overflow_reported: bool,
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

    fn flush(&mut self, write: impl FnOnce(Vec<u8>) -> Result<(), crate::pty::WriteError>) {
        if self.is_empty() {
            return;
        }
        match write(std::mem::take(&mut self.bytes)) {
            Ok(()) => *self = Self::default(),
            Err(crate::pty::WriteError::Full(bytes)) => self.bytes = bytes,
            Err(crate::pty::WriteError::Closed(_)) => {
                tracing::warn!("PTY input closed; pending input discarded");
                *self = Self::default();
            }
        }
    }
}

/// The hosted program: a process on a PTY, and its emulator.
struct PtyHost {
    emu: ServerTerminal,
    pty: crate::pty::Pty,
}

impl PtyHost {
    /// Start `command` (empty for `$SHELL`) through `launcher` at the default size, left to
    /// `reaper` once closed; the host and a receiver of its output. Blocks until the program starts.
    fn spawn(
        command: &[String],
        scrollback: usize,
        launcher: &crate::pty::Launcher,
        reaper: &crate::pty::Reaper,
    ) -> anyhow::Result<(Self, mpsc::Receiver<Vec<u8>>)> {
        let Size { rows, cols } = DEFAULT_SIZE;
        let emu = ServerTerminal::new(rows, cols, scrollback)
            .context("creating the terminal emulator")?;
        let (pty, pty_rx) =
            crate::pty::Pty::spawn(rows, cols, command, "xterm-256color", launcher, reaper)
                .context("spawning shell")?;
        Ok((Self { emu, pty }, pty_rx))
    }

    /// Read the PTY's modes into the emulator, for the next snapshot; whether they changed. Modes
    /// that cannot be read leave the last ones.
    fn refresh_tty(&mut self) -> bool {
        self.pty
            .tty_modes()
            .is_some_and(|tty| self.emu.set_tty(tty))
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
        self.refresh_tty();
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

    /// Queue what the program gets of `input` from the client in `pending`.
    fn apply(&mut self, input: super::ToSession, pending: &mut PendingInput) {
        match input {
            super::ToSession::Events(events) => self.emu.encode_input(&events, &mut pending.bytes),
            // A program that subscribed to scheme changes (mode 2031) hears of a new one on its
            // input.
            super::ToSession::Colours(colours) => {
                pending.bytes.extend(self.emu.set_colours(&colours));
            }
        }
    }
}

/// What is known of how the program ended, and so when the session counts it ended: its exit once
/// known and its output drained (or [`DRAIN_MOST`] after the exit), or, its output ended with no
/// exit, hung up after a grace. Every
/// input is named, and the time passed in.
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
pub(super) struct Input {
    pub(super) attach: u64,
    pub(super) input: super::ToSession,
}

/// What a connection asks its session beside input: served whatever the program is doing.
enum Ask {
    /// History rows, answered on `reply`.
    History {
        request: HistoryRequest,
        reply: oneshot::Sender<HistoryReply>,
    },
    /// A client has the final screen: once the program exited, the session ends.
    Ended,
    /// The window of attachment `attach` is now `size` (clamped): asked beside input, so a
    /// resize never waits behind typing the program has not taken.
    Resize { attach: u64, size: Size },
}

/// Whether [`Registry::attach`] created a fresh session or reattached to a running one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachKind {
    /// A brand-new session was spawned for this peer.
    Created,
    /// Reattached; `detached_for` is how long it had no client, `None` if it had one.
    Reattached { detached_for: Option<Duration> },
}

/// What an attach gets: a session, or why not ([`Close::AtCapacity`], [`Close::CouldNotStart`]).
type Attached = Result<(SessionClient, AttachKind), Close>;

/// A connection's handle to its session: watch the screen, send input, ask for history, and
/// detach on drop.
pub struct SessionClient {
    /// The attachment itself: the session counts its clients by its screen receivers, so this is
    /// never cloned, and none is made but for a client.
    screens: watch::Receiver<Arc<TerminalScreen>>,
    /// Where input goes, as attachment number `attach`: the session takes only the newest's.
    pub(super) input: mpsc::Sender<Input>,
    pub(super) attach: u64,
    asks: mpsc::Sender<Ask>,
}

impl SessionClient {
    /// Wait for the next screen the session publishes, or `None` once the session ends.
    pub async fn next_screen(&mut self) -> Option<Arc<TerminalScreen>> {
        self.screens.changed().await.ok()?;
        Some(self.screens.borrow_and_update().clone())
    }

    /// The current screen.
    pub fn screen(&self) -> Arc<TerminalScreen> {
        self.screens.borrow().clone()
    }

    /// The history rows `request` asks for, answered on the receiver returned, which fails if
    /// the session cannot take the ask (it ended, or too many wait).
    pub fn history(&self, request: HistoryRequest) -> oneshot::Receiver<HistoryReply> {
        let (reply, answer) = oneshot::channel();
        let _ = self.asks.try_send(Ask::History { request, reply });
        answer
    }

    /// The client's window is now `size` (clamped); `false` if the session cannot take it yet.
    pub(super) fn resize(&self, size: Size) -> bool {
        let attach = self.attach;
        self.asks.try_send(Ask::Resize { attach, size }).is_ok()
    }

    /// The client has the final screen: the session, its program exited, may end.
    pub async fn ended(&self) {
        let _ = self.asks.send(Ask::Ended).await;
    }
}

// --- the session task -------------------------------------------------------------------------

/// A connection attaches to a session, which answers it.
struct Attach(oneshot::Sender<Attached>);

/// How many attaches may wait for one session; past them, one is refused as at capacity.
const CONTROL_QUEUE: usize = 8;

/// Start a session for `spec`, its program left to `reaper` once closed, answering `first` once it
/// started: the sender that attaches to it, and the task that runs it.
fn start(
    spec: &SessionSpec,
    reaper: &crate::pty::Reaper,
    first: Attach,
) -> (
    mpsc::Sender<Attach>,
    impl std::future::Future<Output = ()> + Send + 'static,
) {
    let (control, control_rx) = mpsc::channel(CONTROL_QUEUE);
    let command = Arc::clone(&spec.command);
    let (scrollback, ttl, launcher) = (spec.scrollback, spec.ttl, spec.launcher.clone());
    let reaper = reaper.clone();
    let task = async move {
        // Forking and the program's exec block, and must hold up no other session.
        let spawned = tokio::task::spawn_blocking(move || {
            PtyHost::spawn(&command, scrollback, &launcher, &reaper)
        })
        .await;
        let (mut host, pty_rx) = match spawned.map_err(anyhow::Error::from).and_then(|s| s) {
            Ok(spawned) => spawned,
            Err(e) => {
                tracing::error!(error = %e, "spawning a session failed");
                let _ = first.0.send(Err(Close::CouldNotStart));
                return;
            }
        };
        let (screens, _) = watch::channel(Arc::new(host.emu.snapshot()));
        let (input, input_rx) = mpsc::channel(INPUT_QUEUE);
        let (asks, asks_rx) = mpsc::channel(ASK_QUEUE);
        let mut session = Session {
            host,
            screens,
            input,
            asks,
            attaches: 0,
        };
        // A requester already gone drops its client, which the session sees as a detach.
        let _ = first.0.send(Ok((session.client(), AttachKind::Created)));
        session
            .run(pty_rx, control_rx, input_rx, asks_rx, ttl)
            .await;
    };
    (control, task)
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
    host: PtyHost,
    /// Its clients are this sender's receivers: no other receiver may exist.
    screens: watch::Sender<Arc<TerminalScreen>>,
    input: mpsc::Sender<Input>,
    asks: mpsc::Sender<Ask>,
    /// How many attaches there were: the newest's number, whose input alone is taken.
    attaches: u64,
}

impl Session {
    /// A new attachment, the newest.
    fn client(&mut self) -> SessionClient {
        self.attaches = self.attaches.saturating_add(1);
        SessionClient {
            screens: self.screens.subscribe(),
            input: self.input.clone(),
            attach: self.attaches,
            asks: self.asks.clone(),
        }
    }

    fn publish(&mut self) {
        self.screens
            .send_replace(Arc::new(self.host.emu.snapshot()));
    }

    /// Run until the program exited and a client acknowledged its final screen, the session is
    /// detached for the whole `ttl`, or the registry ends it.
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
        let mut exited = false;
        // A frame the program is drawing (synchronized output) is not sent half drawn.
        let mut hold = FrameHold::default();
        let mut tty_tick = tokio::time::interval(TTY_TICK);
        tty_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        // The next read of the PTY's modes after output, and the wait before the one after it.
        let mut settle: Option<(Instant, Duration)> = None;

        loop {
            if let Some(exit) = ending.ended(Instant::now()).filter(|_| !exited) {
                // The final screen carries the status, whole even if the program stopped
                // mid-frame. Input goes nowhere from now on.
                self.host.emu.set_exit_code(exit.code());
                self.publish();
                exited = true;
                pending = PendingInput::default();
                // Its output is read no more: a job left writing stops the reader, not wakes it.
                pty_rx.close();
            }
            if !exited {
                pending.flush(|bytes| self.host.pty.write(bytes));
            }
            let reading = !exited && ending.output_ended.is_none();

            tokio::select! {
                chunk = pty_rx.recv(), if reading => {
                    let now = Instant::now();
                    if let Some(chunk) = chunk {
                        ending.last_output = Some(now);
                        self.host.refresh_tty();
                        self.host.emu.process(&chunk);
                        // What is already read, without waiting; the channel's end is left for
                        // `recv`.
                        for _ in 0..OUTPUT_CHUNKS_PER_SNAPSHOT {
                            let Ok(more) = pty_rx.try_recv() else { break };
                            self.host.emu.process(&more);
                        }
                        // Query answers go to the program, not the screen.
                        pending.reply(&self.host.emu.take_host_replies());
                        if let Some(screen) =
                            hold.after_output(&mut self.host.emu, std::time::Instant::now())
                        {
                            self.screens.send_replace(Arc::new(screen));
                        }
                        settle = now.checked_add(TTY_SETTLE).map(|at| (at, TTY_SETTLE));
                    } else {
                        ending.output_ended = Some(now);
                        ending.exit = ending.exit.or_else(|| self.host.exit().map(|e| (e, now)));
                    }
                },
                _ = until(hold.deadline().map(Instant::from_std)) => {
                    if let Some(screen) = hold.expire(&mut self.host.emu, std::time::Instant::now()) {
                        self.screens.send_replace(Arc::new(screen));
                    }
                },
                () = until(ending.deadline().map(|(at, _)| at)), if !exited => {}
                () = until(settle.map(|(at, _)| at)), if !exited => {
                    let wait = settle.map_or(TTY_TICK, |(_, wait)| wait.saturating_mul(2));
                    settle = Instant::now()
                        .checked_add(wait)
                        .filter(|_| wait < TTY_TICK)
                        .map(|at| (at, wait));
                    if detached.is_none() && self.host.refresh_tty() && !hold.holding() {
                        self.publish();
                    }
                }
                // The session holds a sender, so this never ends. Taken while the program cannot,
                // too, and dropped: an old attachment's, or any once the program exited.
                Some(Input { attach, input }) = input_rx.recv(), if pending.is_empty() || exited => {
                    if attach == self.attaches && !exited {
                        self.host.apply(input, &mut pending);
                    }
                },
                Some(ask) = asks_rx.recv() => match ask {
                    Ask::History { request, reply } => {
                        let _ = reply.send(self.host.emu.history(request));
                    }
                    Ask::Ended if exited => break,
                    Ask::Ended => {}
                    Ask::Resize { attach, size } => {
                        if attach == self.attaches && !exited && self.host.resize(size, &mut pending) {
                            self.publish();
                        }
                    }
                },
                msg = control.recv() => match msg {
                    Some(Attach(reply)) => {
                        // The one place the detach is squared with the clients: the last may have
                        // left unseen by the arm below, and it is dated before this attach.
                        if detached.is_none() && self.screens.receiver_count() == 0 {
                            detached = Some(Instant::now());
                        }
                        let detached_for = detached.map(|since| since.elapsed());
                        // A connection already gone drops its client: the session stays detached
                        // since when it was, so an attach that never arrives does not renew its
                        // TTL.
                        let client = self.client();
                        if reply.send(Ok((client, AttachKind::Reattached { detached_for }))).is_ok() {
                            detached = None;
                        } else {
                            // Never attached: the one before is still the newest.
                            self.attaches = self.attaches.saturating_sub(1);
                        }
                    }
                    // The registry ended this session: revoked, or the server is shutting down.
                    None => break,
                },
                () = self.screens.closed(), if detached.is_none() => {
                    detached = Some(Instant::now());
                }
                () = tokio::time::sleep(INPUT_RETRY), if !pending.is_empty() && !exited => {}
                // A program may turn echo off without writing anything (a password prompt printed
                // first): the client hears of it within a tick.
                _ = tty_tick.tick(), if !exited => {
                    let now = Instant::now();
                    ending.exit = ending.exit.or_else(|| self.host.exit().map(|e| (e, now)));
                    if detached.is_none() && self.host.refresh_tty() && !hold.holding() {
                        self.publish();
                    }
                }
                // Detached for the whole TTL.
                () = until(detached.and_then(|since| since.checked_add(ttl))) => break,
            }
        }

        // Ended: the registry sees the closed control channel, clients their closed screens.
        // The teardown is awaited, so the registry's shutdown waits for every program's hang-up.
        drop((control, input_rx, asks_rx));
        let Self { host, .. } = self;
        let _ = tokio::task::spawn_blocking(move || host.pty.close()).await;
    }
}

// --- the registry -----------------------------------------------------------------------------

/// What the registry is asked.
enum Request {
    /// Attach `peer`, answered on `reply`.
    Attach {
        peer: EndpointId,
        reply: oneshot::Sender<Attached>,
    },
    /// End `peer`'s session, if it has one.
    End(EndpointId),
}

/// A handle to the registry task: cheap to clone, one per accept loop.
#[derive(Clone)]
pub struct Registry {
    tx: mpsc::Sender<Request>,
    shutdown: CancellationToken,
    /// What every session's program is left to once closed.
    reaper: crate::pty::Reaper,
}

/// What the registry hosts, and the session TTL.
pub struct SessionSpec {
    pub command: Arc<[String]>,
    pub scrollback: usize,
    pub max_sessions: usize,
    pub ttl: Duration,
    /// The binary each session's program is started through.
    pub launcher: crate::pty::Launcher,
}

/// How often an attach is tried: one that reached a session as it ended is tried again.
const ATTACH_TRIES: usize = 3;

impl Registry {
    /// Spawn the registry task, attaching only the peers `allows` allows when it takes their
    /// attach, and the reaper its sessions' programs are left to: failing to start that fails
    /// here, before any session.
    pub fn spawn(
        spec: SessionSpec,
        allows: impl Fn(&EndpointId) -> bool + Send + 'static,
    ) -> std::io::Result<Self> {
        let reaper = crate::pty::Reaper::start()?;
        let (tx, rx) = mpsc::channel(64);
        let shutdown = CancellationToken::new();
        #[expect(clippy::disallowed_methods, reason = "one registry a server")]
        tokio::spawn(registry_task(
            sessions::Sessions::new(spec, reaper.clone(), Box::new(allows)),
            rx,
            shutdown.clone(),
        ));
        Ok(Self {
            tx,
            shutdown,
            reaper,
        })
    }

    /// Attach `peer` to its session, creating one if it has none.
    pub async fn attach(&self, peer: EndpointId) -> Attached {
        for _ in 0..ATTACH_TRIES {
            let (reply, rx) = oneshot::channel();
            self.tx
                .send(Request::Attach { peer, reply })
                .await
                .map_err(|_closed| Close::CouldNotStart)?;
            // Unanswered: the session ended as it got the attach, and the registry now knows.
            if let Ok(attached) = rx.await {
                return attached;
            }
        }
        Err(Close::CouldNotStart)
    }

    /// End `peer`'s session, its program hung up: the peer may no longer connect.
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
            Request::Attach { peer, reply } => sessions.attach(peer, Attach(reply)),
            Request::End(peer) => sessions.end(peer),
        }
    }
    // `rx` drops only once every session has ended, which `Registry::shutdown` waits for.
    sessions.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::{Ending, Exit, PendingInput, DRAINED, DRAIN_MOST, ENDING_GRACE};
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
            ..PendingInput::default()
        };
        pending.flush(|bytes| Err(crate::pty::WriteError::Full(bytes)));
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
        let pointer = pending.bytes.as_ptr();
        pending.flush(|bytes| Err(crate::pty::WriteError::Full(bytes)));
        assert_eq!(
            pending.bytes.as_ptr(),
            pointer,
            "backpressure retains the buffer"
        );
        pending.flush(|bytes| {
            assert_eq!(bytes, b"typed\x1b[1;1R\x1b[48;24;80;0;0t");
            Ok(())
        });
        assert!(pending.is_empty());
        assert!(!pending.overflow_reported);
        pending.reply(b"next");
        pending.flush(|bytes| Err(crate::pty::WriteError::Closed(bytes)));
        assert!(
            pending.is_empty(),
            "closed writers do not retain pending input"
        );
    }
}
