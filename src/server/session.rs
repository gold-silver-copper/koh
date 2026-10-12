//! Detachable sessions, as tasks.
//!
//! A [`Registry`] task creates, reattaches, caps and reaps them, one
//! per peer. Each session task owns its [`PtyHost`] and publishes every screen on a `watch`
//! channel, attached or not, so a client that reconnects finds the live screen. A connection talks
//! to its session through a [`SessionClient`]: its screen receiver is its attachment, so dropping
//! it detaches.

use std::sync::Arc;
use std::time::Duration;

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

/// Most output chunks taken into one snapshot beyond the first: one snapshot per 8 KiB read had a
/// chatty program allocate gigabytes a second at the largest size. Bounded, so a program that never
/// stops writing cannot starve input.
const OUTPUT_CHUNKS_PER_SNAPSHOT: usize = 64;

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
pub struct PtyHost {
    pub emu: ServerTerminal,
    pub pty: crate::pty::Pty,
}

impl PtyHost {
    /// Start `command` (empty for the login shell) through `launcher` at the default size, left to
    /// `reaper` once closed; the host and a receiver of its output. Blocks until the program starts.
    pub fn spawn(
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

    /// A snapshot of the current screen.
    pub fn snapshot(&mut self) -> TerminalScreen {
        self.emu.snapshot()
    }

    /// Read the PTY's modes into the emulator, for the next snapshot; whether they changed. Modes
    /// that cannot be read leave the last ones.
    pub fn refresh_tty(&mut self) -> bool {
        self.pty
            .tty_modes()
            .is_some_and(|tty| self.emu.set_tty(tty))
    }

    /// The client's window is now `size` (clamped); whether that changed the size.
    pub fn resize(&mut self, size: Size) -> bool {
        if !self.emu.resize(size) {
            return false;
        }
        let size = crate::terminal::host_size(size);
        if let Err(e) = self.pty.resize(size.rows(), size.cols()) {
            tracing::warn!(error = %e, rows = size.rows(), cols = size.cols(), "pty resize failed");
        }
        true
    }

    /// End it ([`Pty::close`](crate::pty::Pty::close)); blocks joining the pump threads, so run it
    /// on `spawn_blocking`.
    pub fn close(self) {
        self.pty.close();
    }
}

/// What a connection sends its session.
pub(crate) enum ClientInput {
    Input(super::ToSession),
    /// History rows, answered on `reply`.
    History {
        request: HistoryRequest,
        reply: oneshot::Sender<HistoryReply>,
    },
}

/// Whether [`Registry::attach`] created a fresh session or reattached to a running one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachKind {
    /// A brand-new session was spawned for this peer.
    Created,
    /// Reattached; `detached_for` is how long it had no client, `None` if it had one.
    Reattached { detached_for: Option<Duration> },
}

/// Why [`Registry::attach`] gave no session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Refused {
    /// The server holds its most sessions, none of them this peer's.
    #[error("server at session capacity")]
    Full,
    /// The session's program could not start, or the server is shutting down.
    #[error("server could not start a session")]
    Failed,
}

/// What an attach gets.
type Attached = Result<(SessionClient, AttachKind), Refused>;

/// A connection's handle to its session: watch the screen, send input, and detach on drop.
pub struct SessionClient {
    /// The attachment itself: the session counts its clients by its screen receivers, so this is
    /// never cloned, and none is made but for a client.
    screens: watch::Receiver<Arc<TerminalScreen>>,
    input: mpsc::Sender<ClientInput>,
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

    /// Where the connection's input goes, apart from the screens it watches.
    pub(crate) fn input(&self) -> SessionInput {
        self.input.clone()
    }

    /// The history rows `request` asks for, or `None` if the session ended. The future holds no
    /// borrow of the client, so it can run on a task of its own.
    pub fn history(
        &self,
        request: HistoryRequest,
    ) -> impl std::future::Future<Output = Option<HistoryReply>> + Send + 'static {
        let input = self.input.clone();
        async move {
            let (reply, rx) = oneshot::channel();
            input
                .send(ClientInput::History { request, reply })
                .await
                .ok()?;
            rx.await.ok()
        }
    }
}

/// A session's bounded input queue, as a connection writes it: room for one input at a time.
pub(crate) type SessionInput = mpsc::Sender<ClientInput>;

// --- the session task -------------------------------------------------------------------------

/// A connection attaches to a session, which answers it.
struct Attach(oneshot::Sender<Attached>);

/// How many attaches may wait for one session; past them, one is refused as at capacity.
const CONTROL_QUEUE: usize = 8;

/// How long the session waits, once the program's output ended or it exited, for the other: its
/// exit, or the rest of its output.
const ENDING_GRACE: Duration = Duration::from_secs(1);

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
                let _ = first.0.send(Err(Refused::Failed));
                return;
            }
        };
        let (screens_tx, screens) = watch::channel(Arc::new(host.snapshot()));
        let (input, input_rx) = mpsc::channel(INPUT_QUEUE);
        let client = SessionClient {
            screens,
            input: input.clone(),
        };
        // A requester already gone drops its client, which the session sees as a detach.
        let _ = first.0.send(Ok((client, AttachKind::Created)));
        session_task(host, pty_rx, control_rx, screens_tx, input, input_rx, ttl).await;
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

/// Where a session is in its life: every arm of [`session_task`] reads it, and none keeps a flag
/// of its own.
enum Phase {
    /// A client is attached, or left unseen: the `closed` arm or an attach settles it.
    Attached,
    /// No client since `since`.
    Detached { since: Instant },
    /// The program exited: its final screen is served until the last client leaves, and the
    /// session is never reattached.
    Exited,
}

/// The program's exit, if it has exited: reaped then.
fn exit_of(host: &mut PtyHost) -> Option<crate::pty::Exit> {
    host.pty
        .try_wait()
        .map_err(|error| tracing::warn!(%error, "waiting for the session's program failed"))
        .ok()
        .flatten()
}

/// Run one session until its program exits and its client leaves, or its detach TTL expires.
/// Its clients are the receivers of `screens_tx`: no other receiver may exist.
async fn session_task(
    mut host: PtyHost,
    mut pty_rx: mpsc::Receiver<Vec<u8>>,
    mut control: mpsc::Receiver<Attach>,
    screens_tx: watch::Sender<Arc<TerminalScreen>>,
    input_tx: mpsc::Sender<ClientInput>,
    mut input_rx: mpsc::Receiver<ClientInput>,
    ttl: Duration,
) {
    // The first client is attached, from `start`.
    let mut phase = Phase::Attached;
    let mut pending = PendingInput::default();
    // Whether the program's output ended, and its exit once seen: looked for at every tick, never
    // waited on, as a program that closed its terminal may run on, and a job it left in the
    // background may hold its terminal open after it exited. Once either is seen (`ending`), the
    // other has `ENDING_GRACE`.
    let mut output_ended = false;
    let mut exit: Option<crate::pty::Exit> = None;
    let mut ending: Option<Instant> = None;

    // A frame the program is drawing (synchronized output) is not sent half drawn.
    let mut hold = FrameHold::default();

    let mut tty_tick = tokio::time::interval(TTY_TICK);
    tty_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        if ending.is_none() && (output_ended || exit.is_some()) {
            ending = Some(Instant::now());
        }
        let grace_over = ending
            .and_then(|at| at.checked_add(ENDING_GRACE))
            .is_some_and(|at| Instant::now() >= at);
        if !matches!(phase, Phase::Exited) && ((output_ended && exit.is_some()) || grace_over) {
            // The program ended: publish a final screen carrying its status, whole even if it
            // stopped mid-frame. There always is one, so a client always sees the end.
            host.emu
                .set_exit_code(exit.unwrap_or(crate::pty::Exit::HungUp).code());
            phase = Phase::Exited;
            screens_tx.send_replace(Arc::new(host.snapshot()));
        }
        // Retry keystrokes the PTY writer queue could not take last pass.
        pending.flush(|bytes| host.pty.write(bytes));
        let can_read_input = pending.is_empty();
        let running = !matches!(phase, Phase::Exited);

        tokio::select! {
            chunk = pty_rx.recv(), if running && !output_ended => {
                if let Some(chunk) = chunk {
                    host.refresh_tty();
                    host.emu.process(&chunk);
                    // What is already read, without waiting; the channel's end is left for `recv`.
                    for _ in 0..OUTPUT_CHUNKS_PER_SNAPSHOT {
                        let Ok(more) = pty_rx.try_recv() else { break };
                        host.emu.process(&more);
                    }
                    let replies = host.emu.take_host_replies();
                    if !replies.is_empty() {
                        // Query answers go to the program, not the screen.
                        pending.reply(&replies);
                        pending.flush(|bytes| host.pty.write(bytes));
                    }
                    if let Some(screen) = hold.after_output(&mut host.emu, std::time::Instant::now()) {
                        screens_tx.send_replace(Arc::new(screen));
                    }
                } else {
                    output_ended = true;
                    exit = exit.or_else(|| exit_of(&mut host));
                }
            },
            _ = until(hold.deadline().map(Instant::from_std)) => {
                if let Some(screen) = hold.expire(&mut host.emu, std::time::Instant::now()) {
                    screens_tx.send_replace(Arc::new(screen));
                }
            },
            () = until(ending.and_then(|at| at.checked_add(ENDING_GRACE))), if running => {}
            input = input_rx.recv(), if can_read_input => {
                // `input_tx` is held below, so this only ends with the task.
                match input {
                    Some(ClientInput::Input(super::ToSession::Events(events))) => {
                        host.emu.encode_input(&events, &mut pending.bytes);
                        pending.flush(|bytes| host.pty.write(bytes));
                    }
                    // A program that subscribed to scheme changes (mode 2031) hears of a new one
                    // on its input.
                    Some(ClientInput::Input(super::ToSession::Colours(colours))) => {
                        pending.bytes = host.emu.set_colours(&colours);
                        pending.flush(|bytes| host.pty.write(bytes));
                    }
                    Some(ClientInput::Input(super::ToSession::Resize(size))) => {
                        if host.resize(size) {
                            host.refresh_tty();
                            // A program that asked for in-band resize reports (mode 2048) hears of
                            // it on its input, after anything typed before.
                            if let Some(report) = host.emu.resize_report() {
                                pending.reply(&report);
                                pending.flush(|bytes| host.pty.write(bytes));
                            }
                            screens_tx.send_replace(Arc::new(host.snapshot()));
                        }
                    }
                    Some(ClientInput::History { request, reply }) => {
                        let _ = reply.send(host.emu.history(request));
                    }
                    None => {}
                }
            },
            msg = control.recv() => match msg {
                Some(Attach(reply)) => {
                    // The one place the phase is squared with the clients: the last may have left
                    // unseen by the arm below, and the detach is dated before this attach.
                    if matches!(phase, Phase::Attached) && screens_tx.receiver_count() == 0 {
                        phase = Phase::Detached { since: Instant::now() };
                    }
                    let detached_for = match phase {
                        // Closed first, so the requester, asking again, finds this session gone
                        // and gets a new one.
                        Phase::Exited => {
                            control.close();
                            break;
                        }
                        Phase::Attached => None,
                        Phase::Detached { since } => Some(since.elapsed()),
                    };
                    let client = SessionClient {
                        screens: screens_tx.subscribe(),
                        input: input_tx.clone(),
                    };
                    // A connection already gone drops its client: the session stays detached
                    // since when it was, so an attach that never arrives does not renew its TTL.
                    if reply
                        .send(Ok((client, AttachKind::Reattached { detached_for })))
                        .is_ok()
                    {
                        phase = Phase::Attached;
                    }
                }
                None => break, // the registry forgot this session: the server is shutting down
            },
            // The last client left, or none is left to see the exit. The only teardown of an
            // exited session, so it watches in every phase but Detached.
            () = screens_tx.closed(), if !matches!(phase, Phase::Detached { .. }) => {
                if matches!(phase, Phase::Exited) {
                    break;
                }
                phase = Phase::Detached { since: Instant::now() };
            }
            _ = pending_input_retry(!pending.is_empty()) => {}
            // A program may turn echo off without writing anything (a password prompt printed
            // first): the client hears of it within a tick.
            _ = tty_tick.tick(), if running => {
                exit = exit.or_else(|| exit_of(&mut host));
                if matches!(phase, Phase::Attached) && host.refresh_tty() && !hold.holding() {
                    screens_tx.send_replace(Arc::new(host.snapshot()));
                }
            }
            // Detached for the whole TTL.
            () = until(match phase {
                Phase::Detached { since } => since.checked_add(ttl),
                Phase::Attached | Phase::Exited => None,
            }) => break,
        }
    }

    // Ended: the registry sees the closed control channel, clients their closed screens and input.
    // The teardown is awaited, so the registry's shutdown waits for every program's hang-up.
    drop((control, screens_tx, input_rx));
    let _ = tokio::task::spawn_blocking(move || host.close()).await;
}

/// A short wait before retrying pending keystrokes; never, with none pending.
async fn pending_input_retry(pending: bool) {
    if pending {
        tokio::time::sleep(Duration::from_millis(10)).await;
    } else {
        std::future::pending::<()>().await;
    }
}

// --- the registry -----------------------------------------------------------------------------

/// What the registry accepts: attach `peer`, answered on `reply`.
struct AttachReq {
    peer: EndpointId,
    reply: oneshot::Sender<Attached>,
}

/// A handle to the registry task: cheap to clone, one per accept loop.
#[derive(Clone)]
pub struct Registry {
    tx: mpsc::Sender<AttachReq>,
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
    /// Spawn the registry task, and the reaper its sessions' programs are left to: failing to
    /// start that fails here, before any session.
    pub fn spawn(spec: SessionSpec) -> std::io::Result<Self> {
        let reaper = crate::pty::Reaper::start()?;
        let (tx, rx) = mpsc::channel(64);
        let shutdown = CancellationToken::new();
        #[expect(clippy::disallowed_methods, reason = "one registry a server")]
        tokio::spawn(registry_task(spec, reaper.clone(), rx, shutdown.clone()));
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
                .send(AttachReq { peer, reply })
                .await
                .map_err(|_closed| Refused::Failed)?;
            // Unanswered: the session ended as it got the attach, and the registry now knows.
            if let Ok(attached) = rx.await {
                return attached;
            }
        }
        Err(Refused::Failed)
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
    spec: SessionSpec,
    reaper: crate::pty::Reaper,
    mut rx: mpsc::Receiver<AttachReq>,
    shutdown: CancellationToken,
) {
    let mut sessions = sessions::Sessions::new(spec, reaper);
    loop {
        let AttachReq { peer, reply } = tokio::select! {
            // A shutdown starts no session for a request still queued.
            biased;
            () = shutdown.cancelled() => break,
            msg = rx.recv() => match msg {
                Some(msg) => msg,
                None => break,
            },
        };
        sessions.attach(peer, Attach(reply));
    }
    // `rx` drops only once every session has ended, which `Registry::shutdown` waits for.
    sessions.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::PendingInput;

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
