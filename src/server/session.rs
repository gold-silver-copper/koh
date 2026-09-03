//! Detachable, reattachable sessions over a pluggable [`SessionHost`].
//!
//! A [`Session`] (a host — by default a PTY + emulator, [`PtyHost`]) outlives any single client
//! connection. For the PTY host a per-session **drain task** owns the PTY output stream and keeps
//! the emulator current *whether or not a client is attached*, so a reconnecting client always
//! re-syncs to the live screen. The default store is keyed by the client's endpoint id — one
//! detachable session per authorized client (matching the allowlist model, [`PtyHosts`]) — or every
//! peer can share one host ([`SharedHost`], KS-01). This is what gives mosh's "close the laptop,
//! reopen, your session is right where you left it" behavior.
//!
//! Concurrency: the drain task and the attached connection loops all lock the shared session
//! briefly (the drain to `process` output, a loop to snapshot / apply input). The drain pulses a
//! [`ChangeSignal`] after each change so every attached loop re-renders promptly (KS-03): it is a
//! `watch` version counter, so a burst of output coalesces into a single wake per loop
//! (mosh-style collapse) and a pulse can never be lost, because each receiver remembers the
//! version it last saw. Lock order is always store → session, so there is no deadlock (the
//! connection loop only ever locks the session).

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::ssp::SyncState;
use crate::terminal::{ServerTerminal, DEFAULT_COLS, DEFAULT_ROWS};
use anyhow::Context;
use iroh::EndpointId;
use tokio::sync::{mpsc, watch, Mutex};
use tokio_util::sync::CancellationToken;

/// Default cadence the reaper sweeps for dead/expired sessions (injectable per call so tests can
/// drive it without a real 5s wait).
pub(crate) const REAP_INTERVAL: Duration = Duration::from_secs(5);

/// Identifies one attached client connection for the lifetime of that connection (KH-01).
///
/// Allocated by the server per admitted connection; a host that serves several viewers at once
/// (a shared host) keys per-client state such as the viewport size on it. The PTY host ignores it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ClientId(u64);

impl ClientId {
    /// Allocate a fresh, process-unique id.
    pub fn next() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        Self(NEXT.fetch_add(1, Ordering::Relaxed))
    }

    /// The raw id (for logs and tests).
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// What the server hosts behind a session: the producer of the synced state and the sink for
/// client input (KH-01).
///
/// This is exactly the contract [`run_attached`](crate::server::run_attached) needs from the
/// classic PTY + emulator pair, lifted into a trait so an embedding binary can host an in-process
/// state (a multiplexer's workspace) instead of a shell. [`PtyHost`] is the default implementation.
///
/// Every method is called under the session lock, so implementations need no interior locking.
pub trait SessionHost: Send + 'static {
    /// The state this host produces and the transport syncs to the client.
    type State: SyncState + Send + 'static;

    /// Produce the state to ship. Rate-gated by the S-03 echo-ack logic exactly as
    /// `ServerTerminal::snapshot` is today, so it may clone freely.
    fn snapshot(&mut self) -> Self::State;

    /// Client keystrokes (already DECCKM-normalized and coalesced, KOH-05).
    fn input(&mut self, bytes: &[u8]);

    /// The client's terminal is now `rows × cols` (already clamped to `[MIN_DIM, MAX_DIM]`).
    fn resize(&mut self, client: ClientId, rows: u16, cols: u16);

    /// Stamp the echo-ack the connection loop computed for *its* client onto a snapshot it just
    /// took (S-03, KS-02). Frame numbers are per connection, so the host never sees them: the
    /// loop owns the input history and debounce, the host only knows where the ack goes in its
    /// state. Called outside the session lock, on the snapshot alone.
    fn stamp_echo_ack(state: &mut Self::State, echo_ack: u64);

    /// Whether the hosted app has DECCKM (application cursor keys) on, for the arrow-key
    /// normalizer. `false` when the notion does not apply.
    fn application_cursor(&self) -> bool {
        false
    }

    /// Whether the hosted program is still running. Once `false` the connection loop starts the
    /// shutdown handshake and the reaper collects the session. The exit code, if any, travels in
    /// the state (see [`crate::client::ClientState::exit_code`]).
    fn alive(&self) -> bool;

    /// A host that changes on its own (not only in response to input) pulses this to wake
    /// **every** attached connection loop (KS-03). Called once when the session handle is built.
    /// Default: ignore (the PTY host's drain task holds the handle itself).
    fn attach_notify(&mut self, _changed: ChangeSignal) {}

    /// One attached client went away (its connection task ended, KS-01).
    fn client_detached(&mut self, _client: ClientId) {}

    /// Best-effort stop of the hosted program while other holders may still reference the
    /// session (teardown with an attached connection, KOH-10). Default: nothing to stop.
    fn kill(&mut self) {}

    /// Final, sole-owner teardown; may block (the PTY host joins its pump threads here). Runs on
    /// `spawn_blocking`. Default: drop.
    fn shutdown(self)
    where
        Self: Sized,
    {
    }
}

/// The classic host: a PTY-spawned program behind a `vt100` emulator, producing
/// [`crate::terminal::TerminalScreen`] snapshots.
pub struct PtyHost {
    pub emu: ServerTerminal,
    pub pty: crate::pty::Pty,
    /// False once the child process has exited (the drain task hit EOF).
    pub child_alive: bool,
}

impl PtyHost {
    /// Spawn the program and its emulator at the default geometry. Returns the host and the PTY
    /// output receiver the drain task consumes.
    ///
    /// `command` is the argv to host (`command[0]` the program); empty means the login shell.
    pub fn spawn(
        command: &[String],
        scrollback: usize,
    ) -> anyhow::Result<(Self, mpsc::Receiver<Vec<u8>>)> {
        let (rows, cols) = (DEFAULT_ROWS, DEFAULT_COLS);
        let emu = ServerTerminal::new(rows, cols, scrollback);
        let (pty, pty_rx) = crate::pty::Pty::spawn(rows, cols, command, "xterm-256color")
            .context("spawning shell")?;
        Ok((
            Self {
                emu,
                pty,
                child_alive: true,
            },
            pty_rx,
        ))
    }
}

impl SessionHost for PtyHost {
    type State = crate::terminal::TerminalScreen;

    fn snapshot(&mut self) -> Self::State {
        self.emu.snapshot()
    }

    fn input(&mut self, bytes: &[u8]) {
        if let Err(e) = self.pty.write_input(bytes) {
            tracing::warn!(error = %e, "pty write failed");
        }
    }

    fn resize(&mut self, _client: ClientId, rows: u16, cols: u16) {
        if let Err(e) = self.pty.resize(rows, cols) {
            // A failed TIOCSWINSZ silently diverges the kernel winsize from the vt100 grid
            // (full-screen-app corruption with no breadcrumb today); warn, but still resize the
            // emulator so the screen geometry keeps tracking the client.
            tracing::warn!(error = %e, rows, cols, "pty resize failed");
        }
        self.emu.resize(rows, cols);
    }

    fn stamp_echo_ack(state: &mut Self::State, echo_ack: u64) {
        state.set_echo_ack(echo_ack);
    }

    fn application_cursor(&self) -> bool {
        self.emu.application_cursor()
    }

    fn alive(&self) -> bool {
        self.child_alive
    }

    fn kill(&mut self) {
        // Log a failed SIGHUP, then force SIGKILL so a SIGHUP-immune child can't keep the reader
        // thread + fds wedged and stop the last `Arc` (hence the `Pty` Drop) from ever running
        // (KOH-10).
        if let Err(e) = self.pty.kill() {
            tracing::warn!(error = %e, "pty kill during teardown failed");
        }
        self.pty.kill_hard();
    }

    fn shutdown(self) {
        // Kills the child and joins both I/O pump threads, so they don't linger as detached threads.
        self.pty.shutdown();
    }
}

/// A long-lived session that survives client disconnects.
pub struct Session<H: SessionHost = PtyHost> {
    pub host: H,
    /// When the last client detached (`None` while any client is attached); drives TTL reaping.
    /// Only stamped once [`attached`](Self::attached) falls to 0, so an overlapping connection
    /// detaching can't mark a session the other connection is still using as reapable.
    pub last_detach: Option<Instant>,
    /// How many client connections are currently attached to this session. For a per-peer session
    /// normally 0 or 1 (two concurrent connections from the same endpoint id share the handle); for
    /// a shared host, every viewer. The detach timer is reference-counted rather than set on the
    /// first detach.
    pub attached: u32,
}

/// The "state changed" broadcast a host pulses and every attached connection loop watches (KS-03).
///
/// A `tokio::sync::watch` version counter rather than a `Notify`: `Notify::notify_one` releases
/// exactly one waiter, so with two viewers on a shared host the second only re-rendered on its
/// timer cap. `watch` wakes every subscriber, and because each receiver remembers the version it
/// last saw, a pulse that lands between a loop's snapshot and its wait is still observed — the
/// property the stored `Notify` permit used to provide, now for any number of viewers. Bursts
/// still coalesce: many pulses before a loop looks are one wake.
#[derive(Clone, Debug)]
pub struct ChangeSignal(watch::Sender<u64>);

impl ChangeSignal {
    fn new() -> Self {
        Self(watch::Sender::new(0))
    }

    /// Announce that the state changed; every subscribed loop wakes once.
    pub fn pulse(&self) {
        self.0.send_modify(|v| *v = v.wrapping_add(1));
    }

    /// A receiver for one connection loop; [`watch::Receiver::changed`] resolves after any pulse
    /// newer than the version the receiver last saw.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.0.subscribe()
    }
}

impl Default for ChangeSignal {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared session plus the signal the host pulses whenever its state changes.
pub struct SessionHandle<H: SessionHost = PtyHost> {
    pub session: Mutex<Session<H>>,
    pub changed: ChangeSignal,
}

impl<H: SessionHost> SessionHandle<H> {
    /// Wrap a host in a handle with a fresh change signal (handed to the host via
    /// [`SessionHost::attach_notify`]), not attached to any client.
    pub fn new(mut host: H) -> SharedSession<H> {
        let changed = ChangeSignal::new();
        host.attach_notify(changed.clone());
        Arc::new(Self {
            session: Mutex::new(Session {
                host,
                last_detach: None,
                attached: 0,
            }),
            changed,
        })
    }
}

pub type SharedSession<H = PtyHost> = Arc<SessionHandle<H>>;
pub type SessionStore<H = PtyHost> = Arc<Mutex<HashMap<EndpointId, SharedSession<H>>>>;

/// Spawn a standalone PTY session: a shell + emulator + a background drain task that keeps the
/// emulator current from the PTY output even with no client attached. Not placed in any store.
///
/// `command` is the argv to host (`command[0]` the program); empty means the login shell.
pub fn spawn_session(command: &[String], scrollback: usize) -> anyhow::Result<SharedSession> {
    let (host, pty_rx) = PtyHost::spawn(command, scrollback)?;
    let handle = SessionHandle::new(host);
    // The drain task is the one long-lived task with no *named* owner (AR-11): it holds an `Arc`
    // clone and ends when its `pty_rx` closes — i.e. once the `Pty` (hence its reader thread) is gone,
    // which happens when the last `SessionHandle` `Arc` drops (after `detach`/`reap` + the connection
    // task exits) or when `teardown` SIGKILLs the child and the reader hits EOF. So it self-terminates
    // on every teardown path without an explicit join; the only thing NOT done is joining the pump
    // threads on a TTL-reap-while-a-connection-still-holds-the-Arc, where `Pty::Drop` reaps them when
    // that last holder finally drops. Giving it a `CancellationToken`/`JoinHandle` is deferred: the
    // cancel must fire ONLY at teardown (never on detach — the drain must keep the emulator current
    // while detached, which is the close-laptop-reopen feature), and that edit is the most dangerous
    // in this subsystem, so it is not worth it while both paths are already leak-free.
    tokio::spawn(drain(handle.clone(), pty_rx));
    Ok(handle)
}

/// Drain PTY output into the emulator for the whole life of the session, pulsing `changed`.
/// Owns `pty_rx` exclusively (it is not `Clone`), so the screen stays current while detached.
async fn drain(handle: SharedSession, mut pty_rx: mpsc::Receiver<Vec<u8>>) {
    loop {
        let Some(chunk) = pty_rx.recv().await else {
            // Shell exited: reader hit EOF. Reap the real exit code (the child is already a
            // zombie, so try_wait returns it) and stamp it onto the emulator so the next
            // snapshot — and thus the shutdown frame — carries it to the client.
            let mut s = handle.session.lock().await;
            s.host.child_alive = false;
            if let Ok(Some(status)) = s.host.pty.try_wait() {
                s.host.emu.set_exit_code(status.exit_code());
            }
            drop(s);
            handle.changed.pulse();
            break;
        };
        let mut s = handle.session.lock().await;
        s.host.emu.process(&chunk);
        // Answer any terminal queries the shell/app emitted (DSR/DA/DECRQM) by writing the
        // replies straight back to the PTY — they are host I/O, not screen content.
        let replies = s.host.emu.take_host_replies();
        if !replies.is_empty() {
            if let Err(e) = s.host.pty.write_input(&replies) {
                // debug, not warn: a just-exited child makes a failed reply write expected and noisy.
                tracing::debug!(error = %e, "pty host-reply write failed");
            }
        }
        drop(s);
        handle.changed.pulse();
    }
}

/// Whether [`attach`] spawned a fresh session or reattached to an existing one.
///
/// Lets the server tell the peer it's resuming a running session (mosh-server's `warn_unattached`,
/// mapped to koh's one-detachable-session-per-peer model: there is never a duplicate to warn about,
/// only a resume).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachKind {
    /// A brand-new session was spawned for this peer.
    Created,
    /// Reattached to an existing session. `detached_for` is how long it had been detached
    /// (`None` if it wasn't marked detached, e.g. a second overlapping connection).
    Reattached { detached_for: Option<Duration> },
}

/// Get-or-create the detachable PTY session for `peer` (see [`attach_with`]).
///
/// `max_sessions` caps the number of distinct live sessions (L-3): reattaching to `peer`'s existing
/// session is always allowed, but creating a NEW session when the store already holds `max_sessions`
/// is refused (returns `Ok(None)`), so a flood of distinct keys can't spawn unbounded shells.
pub async fn attach(
    store: &SessionStore,
    peer: EndpointId,
    command: &[String],
    scrollback: usize,
    max_sessions: usize,
) -> anyhow::Result<Option<(SharedSession, AttachKind)>> {
    attach_with(store, peer, max_sessions, || {
        spawn_session(command, scrollback)
    })
    .await
}

/// Get-or-create the session stored under `key`, building a new one with `make` if absent.
///
/// On reattach, clears the detach timer so the reaper won't collect it while the client is back,
/// and reports how long it had been detached. `max_sessions` is the L-3 cap on live sessions.
pub async fn attach_with<H: SessionHost>(
    store: &SessionStore<H>,
    key: EndpointId,
    max_sessions: usize,
    make: impl FnOnce() -> anyhow::Result<SharedSession<H>>,
) -> anyhow::Result<Option<(SharedSession<H>, AttachKind)>> {
    let mut map = store.lock().await;
    if let Some(h) = map.get(&key) {
        let mut s = h.session.lock().await;
        let detached_for = s.last_detach.map(|t| t.elapsed());
        s.last_detach = None;
        s.attached = s.attached.saturating_add(1);
        drop(s);
        return Ok(Some((h.clone(), AttachKind::Reattached { detached_for })));
    }
    // New key: enforce the live-session cap before building a host.
    if map.len() >= max_sessions {
        return Ok(None);
    }
    let handle = make()?;
    handle.session.lock().await.attached = 1;
    map.insert(key, handle.clone());
    Ok(Some((handle, AttachKind::Created)))
}

/// Detach one client from `peer`'s session (the host keeps running for reattach).
///
/// The detach timer is stamped only when the *last* attached client leaves, so a concurrent
/// connection detaching can't mark a session the other is still using as reapable.
pub async fn detach<H: SessionHost>(store: &SessionStore<H>, peer: EndpointId) {
    if let Some(h) = store.lock().await.get(&peer) {
        let mut s = h.session.lock().await;
        s.attached = s.attached.saturating_sub(1);
        if s.attached == 0 {
            s.last_detach = Some(Instant::now());
        }
    }
}

/// How a server maps admitted peers onto sessions (KH-01).
///
/// One per peer ([`PtyHosts`]), or one for everyone ([`SharedHost`]). The accept loop calls
/// [`attach`](Self::attach) once per admitted connection and the matching [`detach`](Self::detach)
/// / [`reap`](Self::reap) when it ends; the reaper sweeps [`store`](Self::store).
pub trait HostProvider<H: SessionHost>: Send + Sync + 'static {
    /// Get-or-create the session for `peer`. `Ok(None)` refuses a new session (at capacity).
    fn attach(
        &self,
        peer: EndpointId,
    ) -> impl Future<Output = anyhow::Result<Option<(SharedSession<H>, AttachKind)>>> + Send;

    /// One connection from `peer` ended; keep the session for reattach.
    fn detach(&self, peer: EndpointId) -> impl Future<Output = ()> + Send;

    /// `peer`'s hosted program exited and the shutdown handshake completed; tear it down.
    fn reap(&self, peer: EndpointId) -> impl Future<Output = ()> + Send;

    /// The store the TTL reaper sweeps.
    fn store(&self) -> SessionStore<H>;
}

/// The default provider: one detachable PTY session per authorized peer.
#[derive(Clone)]
pub struct PtyHosts {
    store: SessionStore,
    command: Arc<[String]>,
    scrollback: usize,
    max_sessions: usize,
}

impl PtyHosts {
    /// Host `command` (argv; empty = login shell) for each peer, with at most `max_sessions`
    /// distinct live sessions.
    pub fn new(command: Vec<String>, scrollback: usize, max_sessions: usize) -> Self {
        Self {
            store: SessionStore::default(),
            command: command.into(),
            scrollback,
            max_sessions,
        }
    }
}

impl HostProvider<PtyHost> for PtyHosts {
    async fn attach(
        &self,
        peer: EndpointId,
    ) -> anyhow::Result<Option<(SharedSession, AttachKind)>> {
        attach(
            &self.store,
            peer,
            &self.command,
            self.scrollback,
            self.max_sessions,
        )
        .await
    }

    async fn detach(&self, peer: EndpointId) {
        detach(&self.store, peer).await;
    }

    async fn reap(&self, peer: EndpointId) {
        reap(&self.store, peer).await;
    }

    fn store(&self) -> SessionStore {
        self.store.clone()
    }
}

/// One host for every authorized peer (KS-01).
///
/// Built lazily on the first admitted connection; every later peer attaches to the same
/// [`SharedSession`] with its own connection loop, transport and [`ClientId`]. Stored under a
/// single fixed key so the reaper sees one entry; collected only once every viewer has detached
/// and the TTL has elapsed, or when the host exits.
pub struct SharedHost<H: SessionHost> {
    store: SessionStore<H>,
    make: Arc<dyn Fn() -> anyhow::Result<SharedSession<H>> + Send + Sync>,
}

impl<H: SessionHost> SharedHost<H> {
    /// Share one host built by `make` (wrapped in a fresh [`SessionHandle`]).
    pub fn new(make: impl Fn() -> anyhow::Result<H> + Send + Sync + 'static) -> Self {
        Self::new_with_handles(move || Ok(SessionHandle::new(make()?)))
    }

    /// Share one session built by `make` — for hosts that need the handle at construction, such
    /// as a PTY whose drain task holds it: `SharedHost::new_with_handles(|| spawn_session(..))`.
    pub fn new_with_handles(
        make: impl Fn() -> anyhow::Result<SharedSession<H>> + Send + Sync + 'static,
    ) -> Self {
        Self {
            store: SessionStore::default(),
            make: Arc::new(make),
        }
    }

    /// The single store key every peer maps to (a fixed, never-dialable id).
    fn key() -> EndpointId {
        iroh::SecretKey::from_bytes(&[0u8; 32]).public()
    }
}

impl<H: SessionHost> HostProvider<H> for SharedHost<H> {
    async fn attach(
        &self,
        _peer: EndpointId,
    ) -> anyhow::Result<Option<(SharedSession<H>, AttachKind)>> {
        let make = self.make.clone();
        attach_with(&self.store, Self::key(), 1, || make()).await
    }

    async fn detach(&self, _peer: EndpointId) {
        detach(&self.store, Self::key()).await;
    }

    async fn reap(&self, _peer: EndpointId) {
        reap(&self.store, Self::key()).await;
    }

    fn store(&self) -> SessionStore<H> {
        self.store.clone()
    }
}

/// RAII safety net that releases an attached connection's session if its task unwinds (K-16).
///
/// If the per-connection task **panics** before it can run its explicit [`HostProvider::detach`] /
/// [`HostProvider::reap`], this guard's `Drop` still releases the attach — decrementing `attached`
/// and arming the detach timer — so a panicking task can't leak the session forever. Without it a
/// panic skips the post-`await` cleanup, leaving `attached > 0` and `last_detach == None`, which the
/// reaper (keyed on `!alive || detached_expired`) never collects: a zombie shell + PTY pinned for the
/// server's lifetime.
///
/// The release goes through the **provider's** `detach`, not a store lookup by peer id (KS-04): a
/// [`SharedHost`] stores every peer under one fixed key, so a lookup by `peer` would miss and the
/// shared host would never be reaped after a panicking connection task.
///
/// A standard RAII Drop-cleans-up-on-unwind discipline. On the normal return paths the task
/// [`disarm`](Self::disarm)s the guard and does the precise cleanup (detach **vs** reap) itself; the
/// guard only fires on an unexpected unwind. `Drop` can't `await`, so it spawns the async detach onto
/// the current runtime (best-effort: a no-op if no runtime is in scope).
#[must_use = "hold the guard for the connection's lifetime, then disarm() on a normal return"]
pub(crate) struct AttachGuard<H: SessionHost, P: HostProvider<H>> {
    provider: Arc<P>,
    peer: EndpointId,
    armed: bool,
    _host: std::marker::PhantomData<fn() -> H>,
}

impl<H: SessionHost, P: HostProvider<H>> AttachGuard<H, P> {
    /// Arm a guard for a freshly-attached `peer` connection. Hold it across the connection loop.
    pub(crate) fn new(provider: Arc<P>, peer: EndpointId) -> Self {
        Self {
            provider,
            peer,
            armed: true,
            _host: std::marker::PhantomData,
        }
    }

    /// Disable the safety net once the connection returned normally and the caller will run the
    /// precise detach/reap itself. Consumes the guard so its `Drop` becomes a no-op.
    pub(crate) fn disarm(mut self) {
        self.armed = false;
    }
}

impl<H: SessionHost, P: HostProvider<H>> Drop for AttachGuard<H, P> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // Only reached on an unwind (the normal paths disarm first). `detach` locks an async Mutex
        // and `Drop` can't `.await`, so we spawn the balancing detach onto the current runtime — the
        // one fire-and-forget recovery in an otherwise tightly-owned system (AR-12). Accepted
        // residual: if no runtime is in scope (the server is tearing its runtime down) the spawn is
        // a no-op and the attach isn't decremented — but a server abandoning its runtime is
        // abandoning all sessions anyway, and even a leaked attach is collected once the orphaned
        // shell exits (the reaper also reaps on `!alive`), so it is not pinned for the server's
        // lifetime. Do NOT "fix" this with per-connection JoinSet panic-observation — that would
        // complicate the accept loop's deliberate spawn-and-forget shape for a moot window.
        let provider = self.provider.clone();
        let peer = self.peer;
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                provider.detach(peer).await;
                tracing::warn!(
                    %peer,
                    "connection task unwound; released its session attach via the drop guard"
                );
            });
        } else {
            // No runtime in scope (the server is tearing its runtime down): the balancing detach
            // can't be spawned, so this attach is not decremented here. It is NOT a permanent leak —
            // the reaper also collects on `!alive`, so the session is reclaimed once the
            // orphaned shell exits — but make the silent degrade an operator breadcrumb rather than
            // an invisible one.
            tracing::warn!(
                %peer,
                "connection task unwound with no tokio runtime in scope; session attach not \
                 decremented now (reaped later when the shell exits)"
            );
        }
    }
}

/// Remove + tear down `peer`'s session (e.g. once its shutdown handshake has completed).
pub async fn reap<H: SessionHost>(store: &SessionStore<H>, peer: EndpointId) {
    let removed = store.lock().await.remove(&peer);
    if let Some(h) = removed {
        teardown(h).await;
    }
}

/// Tear down a session we have just removed from the store.
///
/// If we now hold the **only** reference (the drain task has already ended — typical once the
/// shell has exited), gracefully shut the host down: [`SessionHost::shutdown`] kills the child and
/// joins both I/O pump threads, so they don't linger as detached threads. The join blocks, so it
/// runs on `spawn_blocking`, never on an async worker. Otherwise some other holder (an attached
/// connection, or the drain task) still owns it, so we just [`SessionHost::kill`] the program and
/// let the threads exit when the last reference drops — joining there would mean reaching into
/// shared state we don't own.
async fn teardown<H: SessionHost>(handle: SharedSession<H>) {
    match Arc::try_unwrap(handle) {
        Ok(h) => {
            let Session { host, .. } = h.session.into_inner();
            tokio::task::spawn_blocking(move || host.shutdown());
        }
        Err(h) => {
            h.session.lock().await.host.kill();
        }
    }
}

/// Background sweeper: reap sessions whose hosted program has exited, or that have been detached
/// longer than `ttl`, every `interval`.
///
/// Runs until the store is dropped. `interval` is injectable (the binary passes [`REAP_INTERVAL`])
/// so tests can drive a sweep without a real multi-second wait. `shutdown` lets the caller stop the
/// reaper cleanly: the loop `select!`s the token against the sleep and returns when cancelled
/// (rather than being `abort()`ed mid-sweep).
pub async fn run_reaper<H: SessionHost>(
    store: SessionStore<H>,
    ttl: Duration,
    interval: Duration,
    shutdown: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = shutdown.cancelled() => return,
        }
        sweep(&store, ttl).await;
    }
}

/// One reaper pass: remove and tear down every session whose host has exited or whose detach
/// timer has run past `ttl`. Public within the crate so tests can drive a sweep deterministically.
pub(crate) async fn sweep<H: SessionHost>(store: &SessionStore<H>, ttl: Duration) {
    let mut map = store.lock().await;
    let mut dead = Vec::new();
    for (peer, h) in map.iter() {
        let s = h.session.lock().await;
        let detached_expired = s.last_detach.is_some_and(|t| t.elapsed() >= ttl);
        if !s.host.alive() || detached_expired {
            dead.push(*peer);
        }
    }
    let doomed: Vec<SharedSession<H>> = dead.iter().filter_map(|peer| map.remove(peer)).collect();
    drop(map); // release the store lock before tearing down (teardown may lock a session)
    for h in doomed {
        teardown(h).await;
    }
}

#[cfg(test)]
pub(crate) mod test_host {
    //! A scripted [`SessionHost`] over the [`GridState`](crate::ssp::testkit::GridState) test
    //! state: records every call, appends input into cell 0, and exits on demand.

    use super::*;
    use crate::ssp::testkit::GridState;

    /// One recorded host call.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum HostCall {
        Input(Vec<u8>),
        Resize(ClientId, u16, u16),
        Detached(ClientId),
        Kill,
    }

    #[derive(Default)]
    pub struct ScriptedHost {
        pub state: GridState,
        pub calls: Vec<HostCall>,
        pub alive: bool,
        pub notify: Option<ChangeSignal>,
    }

    impl ScriptedHost {
        pub fn new() -> Self {
            Self {
                alive: true,
                ..Self::default()
            }
        }

        /// Mark the hosted program exited with `code` (carried in the state).
        pub fn set_exited(&mut self, code: u32) {
            self.alive = false;
            self.state.exit_code = Some(code);
            if let Some(n) = &self.notify {
                n.pulse();
            }
        }
    }

    impl SessionHost for ScriptedHost {
        type State = GridState;

        fn snapshot(&mut self) -> GridState {
            self.state.clone()
        }

        fn stamp_echo_ack(state: &mut GridState, echo_ack: u64) {
            state.echo_ack = echo_ack;
        }

        fn input(&mut self, bytes: &[u8]) {
            self.state
                .cells
                .entry(0)
                .or_default()
                .extend_from_slice(bytes);
            self.calls.push(HostCall::Input(bytes.to_vec()));
        }

        fn resize(&mut self, client: ClientId, rows: u16, cols: u16) {
            self.state.rows = rows;
            self.state.cols = cols;
            self.calls.push(HostCall::Resize(client, rows, cols));
        }

        fn alive(&self) -> bool {
            self.alive
        }

        fn attach_notify(&mut self, changed: ChangeSignal) {
            self.notify = Some(changed);
        }

        fn client_detached(&mut self, client: ClientId) {
            self.calls.push(HostCall::Detached(client));
        }

        fn kill(&mut self) {
            self.alive = false;
            self.calls.push(HostCall::Kill);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_host::{HostCall, ScriptedHost};
    use super::*;
    use crate::transport_iroh::generate_secret_key;

    #[tokio::test]
    async fn a_pulse_wakes_every_subscribed_viewer_not_just_one() {
        // KS-03: two connection loops subscribed to one signal both wake on a single pulse — the
        // `notify_one` bug woke only the first.
        let signal = ChangeSignal::new();
        let mut a = signal.subscribe();
        let mut b = signal.subscribe();
        signal.pulse();
        let both = async {
            a.changed().await.expect("sender alive");
            b.changed().await.expect("sender alive");
        };
        tokio::time::timeout(Duration::from_millis(100), both)
            .await
            .expect("both receivers wake within 100 ms");
    }

    #[tokio::test]
    async fn a_pulse_between_snapshot_and_wait_is_not_lost() {
        // KS-03: the loop marks the signal seen (`borrow_and_update`) before snapshotting; a pulse
        // that lands after that mark must resolve the next `changed()` immediately, and a burst
        // of pulses is one wake.
        let signal = ChangeSignal::new();
        let mut rx = signal.subscribe();
        let _ = rx.borrow_and_update(); // "snapshot taken"
        signal.pulse();
        signal.pulse();
        signal.pulse();
        tokio::time::timeout(Duration::from_millis(100), rx.changed())
            .await
            .expect("the pulse after the mark wakes the loop")
            .expect("sender alive");
        let quiet = tokio::time::timeout(Duration::from_millis(50), rx.changed()).await;
        assert!(quiet.is_err(), "the burst coalesced into one wake");
    }

    #[tokio::test]
    async fn attach_reports_created_then_reattached() {
        // First attach for a peer creates a session; a later attach (after detach) reattaches to
        // the same session and reports how long it was detached — the data the server logs as the
        // mosh-style "resuming your session" notice.
        let store = SessionStore::default();
        let peer = generate_secret_key().public();

        let (h1, kind) = attach(&store, peer, &["sh".to_owned()], 0, 64)
            .await
            .expect("first attach")
            .expect("not at capacity");
        assert_eq!(kind, AttachKind::Created, "first attach creates a session");

        detach(&store, peer).await;
        let (h2, kind) = attach(&store, peer, &["sh".to_owned()], 0, 64)
            .await
            .expect("reattach")
            .expect("not at capacity");
        assert!(
            matches!(
                kind,
                AttachKind::Reattached {
                    detached_for: Some(_)
                }
            ),
            "reattach after a detach reports the detached duration, got {kind:?}"
        );
        assert!(
            Arc::ptr_eq(&h1, &h2),
            "reattach returns the very same session handle, not a new one"
        );

        // Tear the shell down so the drain task ends and nothing lingers.
        let _ = h2.session.lock().await.host.pty.kill();
    }

    #[tokio::test]
    async fn overlapping_detach_does_not_arm_reaper_until_last_client_leaves() {
        // Two concurrent connections from the same peer share one session. The first detach must
        // NOT stamp last_detach (the other client is still using the shell); only the last detach
        // arms the TTL reaper. Otherwise the reaper could collect the session under an active client.
        let store = SessionStore::default();
        let peer = generate_secret_key().public();

        let (h, _) = attach(&store, peer, &["sh".to_owned()], 0, 64)
            .await
            .expect("attach A")
            .expect("not at capacity");
        let (_, _) = attach(&store, peer, &["sh".to_owned()], 0, 64)
            .await
            .expect("attach B")
            .expect("not at capacity");
        assert_eq!(
            h.session.lock().await.attached,
            2,
            "both connections counted"
        );

        detach(&store, peer).await; // A leaves; B still attached
        {
            let s = h.session.lock().await;
            assert_eq!(s.attached, 1, "one client remains");
            assert!(
                s.last_detach.is_none(),
                "detach timer must NOT be armed while a client is still attached"
            );
        }

        detach(&store, peer).await; // B leaves; now truly detached
        {
            let s = h.session.lock().await;
            assert_eq!(s.attached, 0);
            assert!(
                s.last_detach.is_some(),
                "detach timer arms only once the last client leaves"
            );
        }

        let _ = h.session.lock().await.host.pty.kill();
    }

    #[tokio::test]
    async fn attach_guard_releases_the_attach_when_dropped_armed() {
        // K-16: an armed guard dropped without disarm (the panic-unwind case) must release the
        // attach — decrement `attached` to 0 and arm the detach timer — so the reaper can collect
        // the session instead of it leaking with attached>0/last_detach=None forever.
        let provider = Arc::new(PtyHosts::new(vec!["sh".to_owned()], 0, 64));
        let peer = generate_secret_key().public();
        let (h, _) = provider
            .attach(peer)
            .await
            .expect("attach")
            .expect("under cap");
        assert_eq!(h.session.lock().await.attached, 1);

        // Simulate a connection task that unwinds before its explicit cleanup: the guard drops armed.
        {
            let _g = AttachGuard::new(provider.clone(), peer);
        }
        // Drop spawns the async detach; give the runtime a few turns to run it.
        let mut released = false;
        for _ in 0..100 {
            {
                let s = h.session.lock().await;
                if s.attached == 0 && s.last_detach.is_some() {
                    released = true;
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(
            released,
            "an armed guard's Drop must detach the session (attached->0, detach timer armed)"
        );
        let _ = h.session.lock().await.host.pty.kill();
    }

    #[tokio::test]
    async fn attach_guard_is_a_noop_once_disarmed() {
        // The normal return path disarms the guard and does its own detach/reap; a disarmed guard
        // must NOT also fire (which would double-decrement the refcount).
        let provider = Arc::new(PtyHosts::new(vec!["sh".to_owned()], 0, 64));
        let peer = generate_secret_key().public();
        let (h, _) = provider
            .attach(peer)
            .await
            .expect("attach")
            .expect("under cap");
        assert_eq!(h.session.lock().await.attached, 1);

        AttachGuard::new(provider.clone(), peer).disarm();
        // Let any erroneously-spawned detach run; the count must be unchanged by the disarmed guard.
        tokio::time::sleep(Duration::from_millis(20)).await;
        let s = h.session.lock().await;
        assert_eq!(
            s.attached, 1,
            "a disarmed guard must not release the attach"
        );
        assert!(
            s.last_detach.is_none(),
            "a disarmed guard must not arm the detach timer"
        );
        drop(s);
        let _ = h.session.lock().await.host.pty.kill();
    }

    #[tokio::test]
    async fn attach_guard_releases_a_shared_host_attach_under_the_shared_key() {
        // KS-04: a SharedHost stores every peer under one fixed key. An armed guard dropping for
        // a peer must still release that shared entry (attached -> 0, detach timer armed); a
        // store lookup by the peer's own id would miss it and pin the host forever.
        let provider = Arc::new(SharedHost::new(|| Ok(ScriptedHost::new())));
        let peer = generate_secret_key().public();
        let (h, _) = provider
            .attach(peer)
            .await
            .expect("attach")
            .expect("under cap");
        assert_eq!(h.session.lock().await.attached, 1);
        {
            let _g = AttachGuard::new(provider.clone(), peer);
        }
        let mut released = false;
        for _ in 0..100 {
            {
                let s = h.session.lock().await;
                if s.attached == 0 && s.last_detach.is_some() {
                    released = true;
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(
            released,
            "the guard must release the shared entry, not look the peer up by its own id"
        );
    }

    #[tokio::test]
    async fn attach_enforces_session_cap_but_allows_reattach() {
        // L-3: with a cap of 2, a third DISTINCT peer is refused (Ok(None)) — a flood of keys can't
        // spawn unbounded shells — but an already-present peer can always reattach.
        let store = SessionStore::default();
        let p1 = generate_secret_key().public();
        let p2 = generate_secret_key().public();
        let p3 = generate_secret_key().public();

        let (h1, _) = attach(&store, p1, &["sh".to_owned()], 0, 2)
            .await
            .expect("attach p1")
            .expect("under cap");
        let (h2, _) = attach(&store, p2, &["sh".to_owned()], 0, 2)
            .await
            .expect("attach p2")
            .expect("under cap");

        // Store is now full (2/2): a brand-new peer is refused.
        let rejected = attach(&store, p3, &["sh".to_owned()], 0, 2)
            .await
            .expect("attach p3 ok-result");
        assert!(
            rejected.is_none(),
            "a new peer beyond the cap must be refused"
        );

        // But an existing peer reattaches fine even at capacity.
        detach(&store, p1).await;
        let reattach = attach(&store, p1, &["sh".to_owned()], 0, 2)
            .await
            .expect("reattach p1")
            .expect("reattach is allowed at capacity");
        assert!(
            matches!(reattach.1, AttachKind::Reattached { .. }),
            "an existing peer reattaches at capacity, got {:?}",
            reattach.1
        );

        for h in [h1, h2] {
            let _ = h.session.lock().await.host.pty.kill();
        }
    }

    #[tokio::test]
    async fn reaper_collects_dead_session_at_injected_interval() {
        // Inject a 10ms sweep interval instead of the 5s default, so the reaper's collection of a
        // dead session is observable in a fast, deterministic test.
        let store = SessionStore::default();
        let peer = generate_secret_key().public();

        // A real session whose shell we immediately mark as exited.
        let handle = spawn_session(&["sh".to_owned()], 0).expect("spawn session");
        handle.session.lock().await.host.child_alive = false;
        store.lock().await.insert(peer, handle);
        assert_eq!(
            store.lock().await.len(),
            1,
            "session is present before the sweep"
        );

        let shutdown = CancellationToken::new();
        let task = tokio::spawn(run_reaper(
            store.clone(),
            Duration::from_secs(3600), // long TTL: collection is driven by child_alive, not TTL
            Duration::from_millis(10),
            shutdown.clone(),
        ));

        let mut reaped = false;
        for _ in 0..200 {
            if store.lock().await.is_empty() {
                reaped = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // Graceful stop: cancel the token and the reaper future resolves on its own (no abort()).
        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("reaper must exit promptly after cancellation")
            .expect("reaper task should not panic");
        assert!(
            reaped,
            "the reaper must collect the dead session at the injected interval"
        );
    }

    // --- KH-01 / KS-01: the same store semantics over a non-PTY host ---

    #[tokio::test]
    async fn pty_host_snapshot_input_and_exit_match_the_pre_trait_behaviour() {
        // KH-01: the PTY host behind the trait is today's code moved, not rewritten — spawn a
        // program with arguments, drain until its output is on the snapshot, then observe the
        // exit code the drain stamped.
        let handle = spawn_session(
            &[
                "sh".to_owned(),
                "-c".to_owned(),
                "printf HELLO; exit 3".to_owned(),
            ],
            0,
        )
        .expect("spawn");
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let mut s = handle.session.lock().await;
            let snap = s.host.snapshot();
            if snap.screen().contents().contains("HELLO") && !s.host.alive() {
                assert_eq!(snap.exit_code(), Some(3), "exit code rides on the snapshot");
                break;
            }
            drop(s);
            assert!(Instant::now() < deadline, "timed out waiting for the child");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn scripted_host_attach_detach_and_reap_follow_the_pty_semantics() {
        // KH-01: attach/detach/reap over a non-PTY host reproduce the per-peer outcomes above.
        let store: SessionStore<ScriptedHost> = SessionStore::default();
        let peer = generate_secret_key().public();
        let (h, kind) = attach_with(&store, peer, 64, || {
            Ok(SessionHandle::new(ScriptedHost::new()))
        })
        .await
        .expect("attach")
        .expect("under cap");
        assert_eq!(kind, AttachKind::Created);
        detach(&store, peer).await;
        let (h2, kind) = attach_with(&store, peer, 64, || {
            Ok(SessionHandle::new(ScriptedHost::new()))
        })
        .await
        .expect("reattach")
        .expect("under cap");
        assert!(matches!(kind, AttachKind::Reattached { .. }));
        assert!(Arc::ptr_eq(&h, &h2));
        detach(&store, peer).await;
        reap(&store, peer).await;
        assert!(store.lock().await.is_empty(), "reap removes the entry");
    }

    #[tokio::test]
    async fn shared_host_hands_every_peer_the_same_session() {
        // KS-01: two distinct peers attach to ONE host; the second attach is a reattach onto the
        // same handle with attached == 2, and the host only sees one construction.
        let built = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let b = built.clone();
        let provider = SharedHost::new(move || {
            b.fetch_add(1, Ordering::Relaxed);
            Ok(ScriptedHost::new())
        });
        let p1 = generate_secret_key().public();
        let p2 = generate_secret_key().public();
        let (h1, k1) = provider.attach(p1).await.expect("attach p1").expect("cap");
        let (h2, k2) = provider.attach(p2).await.expect("attach p2").expect("cap");
        assert_eq!(k1, AttachKind::Created);
        assert!(matches!(k2, AttachKind::Reattached { detached_for: None }));
        assert!(Arc::ptr_eq(&h1, &h2), "both peers share one session");
        assert_eq!(h1.session.lock().await.attached, 2);
        assert_eq!(built.load(Ordering::Relaxed), 1, "the host is built once");

        // Detaching one peer must not arm the reaper while the other is attached.
        provider.detach(p1).await;
        assert!(h1.session.lock().await.last_detach.is_none());
        provider.detach(p2).await;
        assert!(h1.session.lock().await.last_detach.is_some());
        assert_eq!(provider.store().lock().await.len(), 1, "one store entry");
    }

    #[tokio::test]
    async fn reaper_never_reaps_a_shared_host_with_a_viewer_attached() {
        // KS-01: with a 1 ms TTL and a 5 ms sweep, a host with attached > 0 survives many sweeps;
        // the moment the last viewer detaches, it is collected (and `kill` is called on it because
        // the test still holds an Arc).
        let provider = SharedHost::new(|| Ok(ScriptedHost::new()));
        let p1 = generate_secret_key().public();
        let (h, _) = provider.attach(p1).await.expect("attach").expect("cap");
        let store = provider.store();
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(run_reaper(
            store.clone(),
            Duration::from_millis(1),
            Duration::from_millis(5),
            shutdown.clone(),
        ));
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(store.lock().await.len(), 1, "attached host survives sweeps");
        provider.detach(p1).await;
        let mut reaped = false;
        for _ in 0..200 {
            if store.lock().await.is_empty() {
                reaped = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
        assert!(
            reaped,
            "the reaper collects the host once every viewer left"
        );
        assert!(
            h.session.lock().await.host.calls.contains(&HostCall::Kill),
            "teardown with a live Arc elsewhere kills the host"
        );
    }

    #[tokio::test]
    async fn reaper_collects_a_scripted_host_once_it_exits() {
        // KH-01: `alive()` is what the reaper keys on, for any host — a scripted host marked
        // exited is collected on the next sweep even with a long TTL.
        let provider = SharedHost::new(|| Ok(ScriptedHost::new()));
        let peer = generate_secret_key().public();
        let (h, _) = provider.attach(peer).await.expect("attach").expect("cap");
        h.session.lock().await.host.set_exited(9);
        assert_eq!(h.session.lock().await.host.snapshot().exit_code, Some(9));
        drop(h);
        let store = provider.store();
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(run_reaper(
            store.clone(),
            Duration::from_secs(3600),
            Duration::from_millis(5),
            shutdown.clone(),
        ));
        let mut reaped = false;
        for _ in 0..200 {
            if store.lock().await.is_empty() {
                reaped = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
        assert!(
            reaped,
            "an exited host is reaped regardless of TTL or attach count"
        );
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(128))]

        /// KS-01 / KS-04: arbitrary attach/detach/reap/sweep/unwind sequences over a shared host
        /// never drive `attached` negative (saturating), never reap while a viewer is attached,
        /// always reap once `attached == 0` and the TTL has elapsed, and an unwinding connection
        /// task (an armed guard dropping) behaves exactly like a detach.
        #[test]
        fn shared_host_refcount_and_reaping_invariants(
            ops in proptest::collection::vec(0u8..5, 1..40),
        ) {
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            rt.block_on(async {
                let provider = Arc::new(SharedHost::new(|| Ok(ScriptedHost::new())));
                let peers: Vec<EndpointId> = (0..3).map(|_| generate_secret_key().public()).collect();
                let mut attached: u32 = 0;
                let mut alive_entry = false;
                for (i, op) in ops.iter().enumerate() {
                    let peer = peers[i % peers.len()];
                    match op {
                        0 => {
                            provider.attach(peer).await.unwrap().unwrap();
                            attached += 1;
                            alive_entry = true;
                        }
                        1 => {
                            provider.detach(peer).await;
                            attached = attached.saturating_sub(1);
                        }
                        2 => {
                            provider.reap(peer).await;
                            attached = 0;
                            alive_entry = false;
                        }
                        4 => {
                            // A connection task unwinds: its armed guard drops and spawns the
                            // balancing detach; yield so the current-thread runtime runs it.
                            drop(AttachGuard::new(provider.clone(), peer));
                            for _ in 0..4 {
                                tokio::task::yield_now().await;
                            }
                            attached = attached.saturating_sub(1);
                        }
                        _ => {
                            // One reaper sweep with an expired TTL: collects iff nobody is attached.
                            sweep(&provider.store(), Duration::ZERO).await;
                            if attached == 0 {
                                alive_entry = false;
                            }
                        }
                    }
                    let store = provider.store();
                    let map = store.lock().await;
                    proptest::prop_assert_eq!(map.len(), usize::from(alive_entry), "entry presence");
                    if let Some(h) = map.values().next() {
                        let s = h.session.lock().await;
                        proptest::prop_assert_eq!(s.attached, attached, "refcount");
                        proptest::prop_assert!(
                            s.attached > 0 || s.last_detach.is_some(),
                            "a fully detached host always has the detach timer armed"
                        );
                    }
                }
                Ok(())
            })?;
        }
    }
}
