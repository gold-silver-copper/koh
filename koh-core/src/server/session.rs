//! Detachable, reattachable PTY sessions, as tasks.
//!
//! A [`Registry`] task owns the set of live sessions, one per authorized peer, and creates,
//! reattaches, caps and reaps them. Each session is its own task that owns its
//! [`PtyHost`], drains its PTY output into the emulator, and publishes each new screen on a
//! `watch` channel — whether or not a client is attached, so a reconnecting client re-syncs to the
//! live screen ("close the laptop, reopen, it's right where you left off"). A connection talks to
//! its session only through a [`SessionClient`]: it watches the screen and sends input, and
//! dropping it detaches. Session state is owned by its task, never shared behind a lock.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::terminal::{ServerTerminal, TerminalScreen, DEFAULT_COLS, DEFAULT_ROWS};
use anyhow::Context;
use iroh::EndpointId;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::{Instant, MissedTickBehavior};
use tokio_util::sync::CancellationToken;

/// How often the registry sweeps for sessions past their detach TTL. Injectable so tests need no
/// real multi-second wait.
pub(crate) const REAP_INTERVAL: Duration = Duration::from_secs(5);

/// How much input may wait for a session's PTY before a connection must stop reading its stream.
const INPUT_QUEUE: usize = 256;

/// The hosted program: a PTY-spawned process behind a `fux-vt` emulator. Owned by one session task.
pub struct PtyHost {
    pub emu: ServerTerminal,
    pub pty: crate::pty::Pty,
}

impl PtyHost {
    /// Spawn the program and its emulator at the default geometry, returning the host and the PTY
    /// output receiver the session task drains. `command[0]` is the program; empty means the login
    /// shell.
    pub fn spawn(
        command: &[String],
        scrollback: usize,
    ) -> anyhow::Result<(Self, mpsc::Receiver<Vec<u8>>)> {
        let (rows, cols) = (DEFAULT_ROWS, DEFAULT_COLS);
        let emu = ServerTerminal::new(rows, cols, scrollback)
            .context("creating the terminal emulator")?;
        let (pty, pty_rx) = crate::pty::Pty::spawn(rows, cols, command, "xterm-256color")
            .context("spawning shell")?;
        Ok((Self { emu, pty }, pty_rx))
    }

    /// A snapshot of the current screen.
    pub fn snapshot(&self) -> TerminalScreen {
        self.emu.snapshot()
    }

    /// Queue client keystrokes (already DECCKM-normalized) for the PTY. `false` if the writer queue
    /// is full because the program is not reading its input; the caller keeps the bytes and retries.
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

    /// The client's terminal is now `rows × cols` (already clamped to `[MIN_DIM, MAX_DIM]`).
    pub fn resize(&mut self, rows: u16, cols: u16) {
        if let Err(e) = self.pty.resize(rows, cols) {
            tracing::warn!(error = %e, rows, cols, "pty resize failed");
        }
        self.emu.resize(rows, cols);
    }

    /// Stop the program while a pump thread may still reference it, without joining (best-effort).
    pub fn kill(&mut self) {
        if let Err(e) = self.pty.kill() {
            tracing::warn!(error = %e, "pty kill during teardown failed");
        }
        self.pty.kill_hard();
    }

    /// Final, sole-owner teardown. Blocks joining the pump threads, so run it on `spawn_blocking`.
    pub fn shutdown(self) {
        self.pty.shutdown();
    }
}

/// What a connection sends its session.
enum ClientInput {
    Keys(Vec<u8>),
    Resize { rows: u16, cols: u16 },
}

/// Whether [`Registry::attach`] created a fresh session or reattached to a running one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachKind {
    /// A brand-new session was spawned for this peer.
    Created,
    /// Reattached to an existing session; `detached_for` is how long it had been detached (`None`
    /// if a client was still attached).
    Reattached { detached_for: Option<Duration> },
}

/// A connection's handle to its session: watch the screen, send input, and detach on drop.
pub struct SessionClient {
    screens: watch::Receiver<Arc<TerminalScreen>>,
    input: mpsc::Sender<ClientInput>,
    /// Detaches the session when this client is dropped (including on a panic).
    control: mpsc::Sender<SessionMsg>,
}

impl Drop for SessionClient {
    fn drop(&mut self) {
        // Best-effort: the session task decrements its attach count and, at zero, starts the TTL.
        let _ = self.control.try_send(SessionMsg::Detach);
    }
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

    /// Reserve a slot to send input; `None` if the session ended. Awaiting the returned permit-free
    /// send never blocks the caller's loop indefinitely (the queue is bounded, so a full queue is
    /// itself the backpressure).
    pub fn can_send(&self) -> bool {
        !self.input.is_closed()
    }

    /// Send keystrokes to the PTY, waiting for queue room (bounded, so it applies backpressure).
    pub async fn send_keys(&self, keys: Vec<u8>) {
        let _ = self.input.send(ClientInput::Keys(keys)).await;
    }

    /// Send a resize to the PTY.
    pub async fn send_resize(&self, rows: u16, cols: u16) {
        let _ = self.input.send(ClientInput::Resize { rows, cols }).await;
    }
}

// --- the session task -------------------------------------------------------------------------

/// Control messages to a session task.
enum SessionMsg {
    /// A connection attaches; the reply carries a client handle and how long it was detached. The
    /// `control` sender is handed back inside the client so its drop detaches.
    Attach {
        control: mpsc::Sender<Self>,
        reply: oneshot::Sender<(SessionClient, Option<Duration>)>,
    },
    /// A connection detached (its [`SessionClient`] dropped).
    Detach,
}

/// A registry's handle to one session task.
struct SessionHandle {
    control: mpsc::Sender<SessionMsg>,
}

/// Run one session: own the PTY host, drain its output into the emulator, publish each screen,
/// apply attached connections' input, and end when the shell exits or the detach TTL expires.
async fn session_task(
    peer: EndpointId,
    mut host: PtyHost,
    mut pty_rx: mpsc::Receiver<Vec<u8>>,
    mut control: mpsc::Receiver<SessionMsg>,
    ttl: Duration,
    ended: mpsc::Sender<EndpointId>,
) {
    let (screens_tx, _screens_rx) = watch::channel(Arc::new(host.snapshot()));
    let (input_tx, mut input_rx) = mpsc::channel::<ClientInput>(INPUT_QUEUE);
    let input_tx = Arc::new(input_tx);
    let mut attached: usize = 0;
    let mut last_detach: Option<Instant> = None;
    let mut pending_keys: Vec<u8> = Vec::new();
    // Once the shell exits we publish a final screen (with its exit code) and keep the task alive,
    // still serving that screen, until the attached client has seen it and detached (or the TTL).
    let mut exited = false;

    // Check the detach TTL at most every `REAP_INTERVAL`, but sooner for a short TTL (tests).
    let tick_period = ttl.min(REAP_INTERVAL).max(Duration::from_millis(1));
    let mut ttl_tick = tokio::time::interval(tick_period);
    ttl_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        // Retry keystrokes the PTY writer queue could not take last pass.
        if !pending_keys.is_empty() && host.input(&pending_keys) {
            pending_keys.clear();
        }
        let can_read_input = pending_keys.is_empty();

        tokio::select! {
            chunk = pty_rx.recv(), if !exited => {
                if let Some(chunk) = chunk {
                    host.emu.process(&chunk);
                    let replies = host.emu.take_host_replies();
                    if !replies.is_empty() {
                        // Query answers (DSR/DA/DECRQM) are host I/O, not screen content.
                        let _ = host.input(&replies);
                    }
                } else {
                    // The shell exited: reap its status and publish a final screen carrying it. The
                    // task stays alive so the attached connection can deliver that frame and be
                    // acknowledged before we tear down.
                    if let Some(code) = reap_exit_code(&mut host).await {
                        host.emu.set_exit_code(code);
                    }
                    exited = true;
                }
                screens_tx.send_replace(Arc::new(host.snapshot()));
            },
            input = input_rx.recv(), if can_read_input => {
                // `input_tx` is held below, so this only ends with the task.
                if let Some(input) = input {
                    match input {
                        ClientInput::Keys(keys) => {
                            if !host.input(&keys) {
                                pending_keys = keys;
                            }
                        }
                        ClientInput::Resize { rows, cols } => {
                            host.resize(rows, cols);
                            screens_tx.send_replace(Arc::new(host.snapshot()));
                        }
                    }
                }
            },
            msg = control.recv() => match msg {
                Some(SessionMsg::Attach { control, reply }) => {
                    let detached_for = last_detach.take().map(|t| t.elapsed());
                    attached = attached.saturating_add(1);
                    let client = SessionClient {
                        screens: screens_tx.subscribe(),
                        input: (*input_tx).clone(),
                        control,
                    };
                    // If the connection is already gone, treat it as an immediate detach.
                    if reply.send((client, detached_for)).is_err() {
                        attached = attached.saturating_sub(1);
                        if attached == 0 {
                            last_detach = Some(Instant::now());
                        }
                    }
                }
                Some(SessionMsg::Detach) => {
                    attached = attached.saturating_sub(1);
                    if attached == 0 {
                        if exited {
                            break; // the client saw the exit and left; tear down now
                        }
                        last_detach = Some(Instant::now());
                    }
                }
                None => break, // the registry dropped: the whole server is shutting down
            },
            _ = pending_input_retry(!pending_keys.is_empty()) => {}
            _ = ttl_tick.tick() => {
                let idle_expired = last_detach.is_some_and(|t| t.elapsed() >= ttl);
                if attached == 0 && (exited || idle_expired) {
                    break;
                }
            }
        }
    }

    let _ = ended.send(peer).await;
    tokio::task::spawn_blocking(move || host.shutdown());
}

/// A short delay used to re-poll the PTY writer queue while keystrokes are pending; a never-ready
/// future when nothing is pending.
async fn pending_input_retry(pending: bool) {
    if pending {
        tokio::time::sleep(Duration::from_millis(10)).await;
    } else {
        std::future::pending::<()>().await;
    }
}

/// Poll for the exited child's status for up to a second (the zombie becomes waitable a moment
/// after EOF).
async fn reap_exit_code(host: &mut PtyHost) -> Option<u32> {
    // An unrepresentable deadline (a timeout of centuries) means no deadline.
    let deadline = Instant::now().checked_add(Duration::from_secs(1));
    loop {
        match host.pty.try_wait() {
            Ok(Some(status)) => return Some(status.exit_code()),
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

/// What the registry accepts.
enum RegMsg {
    Attach {
        peer: EndpointId,
        reply: oneshot::Sender<Option<(SessionClient, AttachKind)>>,
    },
    /// A session task ended and removed itself.
    Ended(EndpointId),
}

/// A handle to the registry task: cheap to clone, one per accept loop.
#[derive(Clone)]
pub struct Registry {
    tx: mpsc::Sender<RegMsg>,
    shutdown: CancellationToken,
}

/// What the registry hosts, and the session TTL.
pub struct SessionSpec {
    pub command: Arc<[String]>,
    pub scrollback: usize,
    pub max_sessions: usize,
    pub ttl: Duration,
}

impl Registry {
    /// Spawn the registry task.
    pub fn spawn(spec: SessionSpec) -> Self {
        let (tx, rx) = mpsc::channel(64);
        let shutdown = CancellationToken::new();
        tokio::spawn(registry_task(spec, rx, tx.clone(), shutdown.clone()));
        Self { tx, shutdown }
    }

    /// Attach `peer` to its session, creating one if needed. `None` if the server is at its
    /// session cap and `peer` has no existing session.
    pub async fn attach(&self, peer: EndpointId) -> Option<(SessionClient, AttachKind)> {
        let (reply, rx) = oneshot::channel();
        self.tx.send(RegMsg::Attach { peer, reply }).await.ok()?;
        rx.await.ok().flatten()
    }

    /// Stop the registry and every session, and wait for them to tear down.
    pub async fn shutdown(self) {
        self.shutdown.cancel();
        // Dropping the last sender ends the registry task, which drops every session's control
        // sender, ending each session task.
        self.tx.closed().await;
    }
}

async fn registry_task(
    spec: SessionSpec,
    mut rx: mpsc::Receiver<RegMsg>,
    self_tx: mpsc::Sender<RegMsg>,
    shutdown: CancellationToken,
) {
    let mut sessions: HashMap<EndpointId, SessionHandle> = HashMap::new();
    let ended_tx = ended_sender(&self_tx);
    // Drop our own sender clone so the channel closes once the accept loop's `Registry` handles do.
    drop(self_tx);
    loop {
        let msg = tokio::select! {
            () = shutdown.cancelled() => break,
            msg = rx.recv() => match msg {
                Some(msg) => msg,
                None => break,
            },
        };
        match msg {
            RegMsg::Attach { peer, reply } => {
                let result = attach_in(&mut sessions, &spec, &ended_tx, peer).await;
                let _ = reply.send(result);
            }
            RegMsg::Ended(peer) => {
                sessions.remove(&peer);
            }
        }
    }
    // Shutdown: dropping every control sender ends the session tasks.
    sessions.clear();
}

/// The registry's clone of a sender it can hand to session tasks so they announce their end.
fn ended_sender(tx: &mpsc::Sender<RegMsg>) -> mpsc::Sender<EndpointId> {
    let (etx, mut erx) = mpsc::channel::<EndpointId>(16);
    let tx = tx.clone();
    tokio::spawn(async move {
        while let Some(peer) = erx.recv().await {
            if tx.send(RegMsg::Ended(peer)).await.is_err() {
                break;
            }
        }
    });
    etx
}

async fn attach_in(
    sessions: &mut HashMap<EndpointId, SessionHandle>,
    spec: &SessionSpec,
    ended: &mpsc::Sender<EndpointId>,
    peer: EndpointId,
) -> Option<(SessionClient, AttachKind)> {
    if let Some(handle) = sessions.get(&peer) {
        let control = handle.control.clone();
        let (reply, rx) = oneshot::channel();
        if control
            .send(SessionMsg::Attach {
                control: control.clone(),
                reply,
            })
            .await
            .is_ok()
        {
            if let Ok((client, detached_for)) = rx.await {
                return Some((client, AttachKind::Reattached { detached_for }));
            }
        }
        // The session task is gone; drop the stale handle and fall through to create a new one.
        sessions.remove(&peer);
    }
    if sessions.len() >= spec.max_sessions {
        return None;
    }
    let (host, pty_rx) = PtyHost::spawn(&spec.command, spec.scrollback)
        .map_err(|e| tracing::error!(error = %e, "spawning a session failed"))
        .ok()?;
    let (control, control_rx) = mpsc::channel(16);
    tokio::spawn(session_task(
        peer,
        host,
        pty_rx,
        control_rx,
        spec.ttl,
        ended.clone(),
    ));
    sessions.insert(peer, SessionHandle { control });
    // Attach to the session we just created.
    let control = sessions.get(&peer)?.control.clone();
    let (reply, rx) = oneshot::channel();
    control
        .send(SessionMsg::Attach {
            control: control.clone(),
            reply,
        })
        .await
        .ok()?;
    let (client, _) = rx.await.ok()?;
    Some((client, AttachKind::Created))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry(max_sessions: usize, ttl: Duration) -> Registry {
        Registry::spawn(SessionSpec {
            command: vec!["sleep".to_owned(), "30".to_owned()].into(),
            scrollback: 0,
            max_sessions,
            ttl,
        })
    }

    /// Attach `peer`, retrying briefly (a just-reaped session may still be clearing).
    async fn attach_kind(reg: &Registry, peer: EndpointId) -> Option<AttachKind> {
        reg.attach(peer).await.map(|(_, kind)| kind)
    }

    #[test]
    fn attach_creates_then_reattaches_the_same_peer() {
        crate::test_runtime::multi_thread(2).block_on(async {
            let reg = registry(4, Duration::from_secs(30));
            let peer = crate::transport_iroh::generate_secret_key().public();
            let (client, kind) = reg.attach(peer).await.expect("first attach");
            assert_eq!(kind, AttachKind::Created);
            let (_c2, kind) = reg.attach(peer).await.expect("second attach");
            assert!(
                matches!(kind, AttachKind::Reattached { .. }),
                "same peer reattaches"
            );
            drop(client);
            reg.shutdown().await;
        });
    }

    #[test]
    fn max_sessions_refuses_a_new_peer_but_allows_a_reattach() {
        crate::test_runtime::multi_thread(2).block_on(async {
            let reg = registry(1, Duration::from_secs(30));
            let a = crate::transport_iroh::generate_secret_key().public();
            let b = crate::transport_iroh::generate_secret_key().public();
            let (a_client, _) = reg
                .attach(a)
                .await
                .expect("A creates the one allowed session");
            assert!(
                reg.attach(b).await.is_none(),
                "a second distinct peer is refused at the cap"
            );
            assert!(
                matches!(
                    attach_kind(&reg, a).await,
                    Some(AttachKind::Reattached { .. })
                ),
                "the existing peer still reattaches at the cap"
            );
            drop(a_client);
            reg.shutdown().await;
        });
    }

    #[test]
    fn the_last_detach_starts_the_ttl_a_concurrent_one_does_not() {
        crate::test_runtime::multi_thread(2).block_on(async {
            let reg = registry(4, Duration::from_millis(150));
            let peer = crate::transport_iroh::generate_secret_key().public();
            let (a, _) = reg.attach(peer).await.expect("A");
            let (b, _) = reg
                .attach(peer)
                .await
                .expect("B (concurrent, same session)");
            // Dropping ONE of two attached clients must not start the TTL.
            drop(a);
            tokio::time::sleep(Duration::from_millis(400)).await;
            assert!(
                matches!(
                    attach_kind(&reg, peer).await,
                    Some(AttachKind::Reattached { .. })
                ),
                "with one client still attached the session must survive past the TTL"
            );
            // Now drop every client; after the TTL the session is reaped and a fresh attach creates one.
            drop(b);
            drop(reg.attach(peer).await.expect("reattach C").0);
            tokio::time::sleep(Duration::from_millis(500)).await;
            assert_eq!(
                attach_kind(&reg, peer).await,
                Some(AttachKind::Created),
                "after the last detach and the TTL the session is gone"
            );
            reg.shutdown().await;
        });
    }

    #[test]
    fn a_session_whose_shell_exited_is_torn_down() {
        crate::test_runtime::multi_thread(2).block_on(async {
            let reg = Registry::spawn(SessionSpec {
                command: vec!["sh".to_owned(), "-c".to_owned(), "exit 0".to_owned()].into(),
                scrollback: 0,
                max_sessions: 4,
                ttl: Duration::from_secs(30),
            });
            let peer = crate::transport_iroh::generate_secret_key().public();
            let (mut client, kind) = reg.attach(peer).await.expect("attach");
            assert_eq!(kind, AttachKind::Created);
            // Wait for the final (exited) screen, then detach.
            for _ in 0..100 {
                if client.screen().exit_code().is_some() {
                    break;
                }
                let _ = tokio::time::timeout(Duration::from_millis(50), client.next_screen()).await;
            }
            assert!(
                client.screen().exit_code().is_some(),
                "the exit code reaches the screen"
            );
            drop(client);
            // The session tears down once the client that saw the exit detaches; a fresh attach creates.
            let mut created = false;
            for _ in 0..100 {
                if attach_kind(&reg, peer).await == Some(AttachKind::Created) {
                    created = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            assert!(
                created,
                "an exited session is torn down and the next attach creates a new one"
            );
            reg.shutdown().await;
        });
    }
}
