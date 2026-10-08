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

/// How often a session reads its PTY's modes when nothing else made it: a password prompt that
/// turned echo off after printing is known to the client within this (the wire's contract).
use crate::proto::TTY_TICK;

/// How much input may wait for a session's PTY before a connection must stop reading its stream.
const INPUT_QUEUE: usize = 256;

/// Most output chunks taken into one snapshot beyond the first: one snapshot per 8 KiB read had a
/// chatty program allocate gigabytes a second at the largest size. Bounded, so a program that never
/// stops writing cannot starve input.
const OUTPUT_CHUNKS_PER_SNAPSHOT: usize = 64;

/// The hosted program: a process on a PTY, and its emulator.
pub struct PtyHost {
    pub emu: ServerTerminal,
    pub pty: crate::pty::Pty,
}

impl PtyHost {
    /// Start `command` (empty for the login shell) through `launcher` at the default size; the host
    /// and a receiver of its output.
    pub fn spawn(
        command: &[String],
        scrollback: usize,
        launcher: &crate::pty::Launcher,
    ) -> anyhow::Result<(Self, mpsc::Receiver<Vec<u8>>)> {
        let Size { rows, cols } = DEFAULT_SIZE;
        let emu = ServerTerminal::new(rows, cols, scrollback)
            .context("creating the terminal emulator")?;
        let (pty, pty_rx) = crate::pty::Pty::spawn(rows, cols, command, "xterm-256color", launcher)
            .context("spawning shell")?;
        Ok((Self { emu, pty }, pty_rx))
    }

    /// A snapshot of the current screen.
    pub fn snapshot(&mut self) -> TerminalScreen {
        self.emu.snapshot()
    }

    /// Read the PTY's modes into the emulator, for the next snapshot; whether they changed.
    pub fn refresh_tty(&mut self) -> bool {
        self.emu.set_tty(self.pty.tty_modes())
    }

    /// Queue keystrokes for the program; `false` if its queue is full, and the caller retries.
    pub fn input(&mut self, bytes: &[u8]) -> bool {
        match self.pty.write_input(bytes) {
            Ok(()) => true,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => false,
            Err(e) => {
                tracing::warn!(error = %e, "pty write failed");
                true // the program is gone; there is no one to deliver to
            }
        }
    }

    /// The client's window is now `size` (clamped).
    pub fn resize(&mut self, size: Size) {
        let Size { rows, cols } = size;
        if let Err(e) = self.pty.resize(rows, cols) {
            tracing::warn!(error = %e, rows, cols, "pty resize failed");
        }
        self.emu.resize(size);
    }

    /// Tear down; blocks joining the pump threads, so run it on `spawn_blocking`.
    pub fn shutdown(self) {
        self.pty.shutdown();
    }
}

/// What a connection sends its session.
enum ClientInput {
    Input(super::ToSession),
    Resize(Size),
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

/// A connection's handle to its session: watch the screen, send input, and detach on drop.
pub struct SessionClient {
    /// The attachment itself: the session counts its clients by its screen receivers, so this is
    /// never cloned, and none is made but for a client ([`start`] and [`Attach`]).
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

    /// Whether the session still takes input: `false` once it ended.
    pub fn can_send(&self) -> bool {
        !self.input.is_closed()
    }

    /// Send input, waiting for room in the bounded queue.
    pub(crate) async fn send_input(&self, input: super::ToSession) {
        let _ = self.input.send(ClientInput::Input(input)).await;
    }

    /// Send a resize to the PTY.
    pub async fn send_resize(&self, size: Size) {
        let _ = self.input.send(ClientInput::Resize(size)).await;
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

// --- the session task -------------------------------------------------------------------------

/// A connection attaches to a session: its client, and how long the session had none.
struct Attach(oneshot::Sender<(SessionClient, Option<Duration>)>);

/// Start a session for `spec`: the sender that attaches to it, its first client, and the task that
/// runs it. The first client exists before the task does, so the session never runs uncounted.
fn start(
    spec: &SessionSpec,
) -> anyhow::Result<(
    mpsc::Sender<Attach>,
    SessionClient,
    impl std::future::Future<Output = ()> + Send + 'static,
)> {
    let (mut host, pty_rx) = PtyHost::spawn(&spec.command, spec.scrollback, &spec.launcher)?;
    let (screens_tx, screens) = watch::channel(Arc::new(host.snapshot()));
    let (input, input_rx) = mpsc::channel(INPUT_QUEUE);
    // The registry waits for each attach's answer before it sends another.
    let (control, control_rx) = mpsc::channel(1);
    let client = SessionClient {
        screens,
        input: input.clone(),
    };
    let task = session_task(
        host, pty_rx, control_rx, screens_tx, input, input_rx, spec.ttl,
    );
    Ok((control, client, task))
}

/// Hand `take` up to `limit` items `rx` already holds, without waiting, as they come off the
/// channel. An end of the channel is left for the next `recv` to report.
fn take_ready<T>(rx: &mut mpsc::Receiver<T>, limit: usize, mut take: impl FnMut(T)) {
    for _ in 0..limit {
        let Ok(item) = rx.try_recv() else {
            break;
        };
        take(item);
    }
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
    let mut pending_keys: Vec<u8> = Vec::new();

    // A frame the program is drawing (synchronized output) is not sent half drawn.
    let mut hold = FrameHold::default();

    let mut tty_tick = tokio::time::interval(TTY_TICK);
    tty_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        // Retry keystrokes the PTY writer queue could not take last pass.
        if !pending_keys.is_empty() && host.input(&pending_keys) {
            pending_keys.clear();
        }
        let can_read_input = pending_keys.is_empty();

        tokio::select! {
            chunk = pty_rx.recv(), if !matches!(phase, Phase::Exited) => {
                if let Some(chunk) = chunk {
                    host.refresh_tty();
                    host.emu.process(&chunk);
                    take_ready(&mut pty_rx, OUTPUT_CHUNKS_PER_SNAPSHOT, |more| {
                        host.emu.process(&more);
                    });
                    let replies = host.emu.take_host_replies();
                    if !replies.is_empty() {
                        // Query answers go to the program, not the screen.
                        let _ = host.input(&replies);
                    }
                    if let Some(screen) = hold.after_output(&mut host.emu, std::time::Instant::now()) {
                        screens_tx.send_replace(Arc::new(screen));
                    }
                } else {
                    // The program exited: publish a final screen carrying its status, whole even
                    // if it stopped mid-frame.
                    if let Some(code) = reap_exit_code(&mut host).await {
                        host.emu.set_exit_code(code);
                    }
                    phase = Phase::Exited;
                    screens_tx.send_replace(Arc::new(host.snapshot()));
                }
            },
            _ = until(hold.deadline().map(Instant::from_std)) => {
                if let Some(screen) = hold.expire(&mut host.emu, std::time::Instant::now()) {
                    screens_tx.send_replace(Arc::new(screen));
                }
            },
            input = input_rx.recv(), if can_read_input => {
                // `input_tx` is held below, so this only ends with the task.
                if let Some(input) = input {
                    match input {
                        ClientInput::Input(input) => {
                            let keys = match input {
                                super::ToSession::Bytes(keys) => keys,
                                super::ToSession::Events(events) => {
                                    let mut keys = Vec::new();
                                    host.emu.encode_input(&events, &mut keys);
                                    keys
                                }
                                // A program that subscribed to scheme changes (mode 2031) hears
                                // of a new one on its input.
                                super::ToSession::Colours(colours) => {
                                    host.emu.set_colours(&colours)
                                }
                            };
                            if !keys.is_empty() && !host.input(&keys) {
                                pending_keys = keys;
                            }
                        }
                        ClientInput::Resize(size) => {
                            host.resize(size);
                            host.refresh_tty();
                            // A program that asked for in-band resize reports (mode 2048) hears of
                            // it on its input, after anything typed before.
                            if let Some(report) = host.emu.resize_report() {
                                if !host.input(&report) {
                                    pending_keys.extend_from_slice(&report);
                                }
                            }
                            screens_tx.send_replace(Arc::new(host.snapshot()));
                        }
                        ClientInput::History { request, reply } => {
                            let _ = reply.send(host.emu.history(request));
                        }
                    }
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
                        // The reply is dropped, so the registry starts a new session.
                        Phase::Exited => break,
                        Phase::Attached => None,
                        Phase::Detached { since } => Some(since.elapsed()),
                    };
                    let client = SessionClient {
                        screens: screens_tx.subscribe(),
                        input: input_tx.clone(),
                    };
                    // A connection already gone drops its client: the session stays detached
                    // since when it was, so an attach that never arrives does not renew its TTL.
                    if reply.send((client, detached_for)).is_ok() {
                        phase = Phase::Attached;
                    }
                }
                None => break, // the registry forgot this session: the server is shutting down
            },
            // The last client left, or none is left to see the exit. The only teardown of an
            // exited session, so it watches in every phase but Detached.
            () = screens_tx.closed(), if !matches!(phase, Phase::Detached { .. }) => match phase {
                Phase::Exited => break,
                Phase::Attached => phase = Phase::Detached { since: Instant::now() },
                Phase::Detached { .. } => {}
            },
            _ = pending_input_retry(!pending_keys.is_empty()) => {}
            // A program may turn echo off without writing anything (a password prompt printed
            // first): the client hears of it within a tick.
            _ = tty_tick.tick(), if matches!(phase, Phase::Attached) => {
                if host.refresh_tty() && !hold.holding() {
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
    drop((control, screens_tx, input_rx));
    tokio::task::spawn_blocking(move || host.shutdown());
}

/// A short wait before retrying pending keystrokes; never, with none pending.
async fn pending_input_retry(pending: bool) {
    if pending {
        tokio::time::sleep(Duration::from_millis(10)).await;
    } else {
        std::future::pending::<()>().await;
    }
}

/// The exited program's status, polled for up to a second: it is waitable a moment after EOF.
async fn reap_exit_code(host: &mut PtyHost) -> Option<u32> {
    let deadline = Instant::now().checked_add(Duration::from_secs(1));
    loop {
        match host.pty.try_wait() {
            Ok(Some(status)) => return Some(status.code),
            Ok(None) if deadline.is_none_or(|d| Instant::now() < d) => {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            Ok(None) => return None,
            Err(error) => {
                tracing::warn!(%error, "waiting for PTY child status after EOF failed");
                return None;
            }
        }
    }
}

// --- the registry -----------------------------------------------------------------------------

/// What the registry accepts: attach `peer`.
struct AttachReq {
    peer: EndpointId,
    reply: oneshot::Sender<Option<(SessionClient, AttachKind)>>,
}

/// A handle to the registry task: cheap to clone, one per accept loop.
#[derive(Clone)]
pub struct Registry {
    tx: mpsc::Sender<AttachReq>,
    shutdown: CancellationToken,
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

impl Registry {
    /// Spawn the registry task.
    pub fn spawn(spec: SessionSpec) -> Self {
        let (tx, rx) = mpsc::channel(64);
        let shutdown = CancellationToken::new();
        tokio::spawn(registry_task(spec, rx, shutdown.clone()));
        Self { tx, shutdown }
    }

    /// Attach `peer` to its session, creating one if needed. `None` if the server is at its
    /// session cap and `peer` has no existing session.
    pub async fn attach(&self, peer: EndpointId) -> Option<(SessionClient, AttachKind)> {
        let (reply, rx) = oneshot::channel();
        self.tx.send(AttachReq { peer, reply }).await.ok()?;
        rx.await.ok().flatten()
    }

    /// Stop the registry and every session, and wait for them to end.
    pub async fn shutdown(self) {
        self.shutdown.cancel();
        self.tx.closed().await;
    }
}

async fn registry_task(
    spec: SessionSpec,
    mut rx: mpsc::Receiver<AttachReq>,
    shutdown: CancellationToken,
) {
    let mut sessions = sessions::Sessions::new(spec);
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
        let _ = reply.send(sessions.attach(peer).await);
    }
    // `rx` drops only once every session has ended, which `Registry::shutdown` waits for.
    sessions.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::{take_ready, OUTPUT_CHUNKS_PER_SNAPSHOT};
    use tokio::sync::mpsc;

    #[test]
    fn a_burst_of_output_is_taken_in_bounded_batches_and_the_end_is_left_for_recv() {
        let (tx, mut rx) = mpsc::channel::<usize>(512);
        for n in 0..100 {
            tx.try_send(n).unwrap();
        }
        let taken = |rx: &mut mpsc::Receiver<usize>| {
            let mut taken = Vec::new();
            take_ready(rx, OUTPUT_CHUNKS_PER_SNAPSHOT, |n| taken.push(n));
            taken
        };
        assert_eq!(
            taken(&mut rx),
            (0..OUTPUT_CHUNKS_PER_SNAPSHOT).collect::<Vec<_>>()
        );
        drop(tx);
        assert_eq!(
            taken(&mut rx),
            (OUTPUT_CHUNKS_PER_SNAPSHOT..100).collect::<Vec<_>>()
        );
        // The channel's end is not swallowed: the session loop's `recv` still sees it and reaps
        // the program.
        assert_eq!(taken(&mut rx), Vec::<usize>::new());
        assert_eq!(rx.try_recv(), Err(mpsc::error::TryRecvError::Disconnected));
    }
}
