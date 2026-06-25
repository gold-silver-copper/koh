//! Detachable, reattachable shell sessions.
//!
//! A [`Session`] (PTY + emulator) outlives any single client connection. A per-session **drain
//! task** owns the PTY output stream and keeps the emulator current *whether or not a client is
//! attached*, so a reconnecting client always re-syncs to the live screen. The store is keyed by
//! the client's endpoint id — one detachable session per authorized client (matching the
//! allowlist model). This is what gives mosh's "close the laptop, reopen, your session is right
//! where you left it" behavior.
//!
//! Concurrency: the drain task and the attached connection loop both lock the shared session
//! briefly (the drain to `process` output, the loop to snapshot / apply input). The drain pulses
//! a [`Notify`] after each change so the attached loop re-renders promptly; `notify_one`
//! coalesces a burst of output into a single wake (mosh-style collapse). Lock order is always
//! store → session, so there is no deadlock (the connection loop only ever locks the session).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::terminal::{ServerTerminal, DEFAULT_COLS, DEFAULT_ROWS};
use anyhow::Context;
use iroh::EndpointId;
use tokio::sync::{mpsc, Mutex, Notify};
use tokio_util::sync::CancellationToken;

/// Default cadence the reaper sweeps for dead/expired sessions (injectable per call so tests can
/// drive it without a real 5s wait).
pub(crate) const REAP_INTERVAL: Duration = Duration::from_secs(5);

/// A long-lived shell session that survives client disconnects.
pub struct Session {
    pub emu: ServerTerminal,
    pub pty: crate::pty::Pty,
    /// False once the shell process has exited (the drain task hit EOF).
    pub child_alive: bool,
    /// When the last client detached (`None` while any client is attached); drives TTL reaping.
    /// Only stamped once [`attached`](Self::attached) falls to 0, so an overlapping same-peer
    /// connection detaching can't mark a session the other connection is still using as reapable.
    pub last_detach: Option<Instant>,
    /// How many client connections are currently attached to this (one-per-peer) session. Normally
    /// 0 or 1, but two concurrent connections from the same endpoint id share the handle, so the
    /// detach timer must be reference-counted rather than set on the first detach.
    pub attached: u32,
}

/// Shared session plus a notifier the drain task pulses whenever the screen changes.
pub struct SessionHandle {
    pub session: Mutex<Session>,
    pub changed: Notify,
}

pub type SharedSession = Arc<SessionHandle>;
pub type SessionStore = Arc<Mutex<HashMap<EndpointId, SharedSession>>>;

/// Spawn a standalone session: a PTY shell + emulator + a background drain task that keeps the
/// emulator current from the PTY output even with no client attached. Not placed in any store.
pub fn spawn_session(shell: Option<&str>, scrollback: usize) -> anyhow::Result<SharedSession> {
    let (rows, cols) = (DEFAULT_ROWS, DEFAULT_COLS);
    let emu = ServerTerminal::new(rows, cols, scrollback);
    let (pty, pty_rx) =
        crate::pty::Pty::spawn(rows, cols, shell, "xterm-256color").context("spawning shell")?;
    let handle = Arc::new(SessionHandle {
        session: Mutex::new(Session {
            emu,
            pty,
            child_alive: true,
            last_detach: None,
            attached: 0,
        }),
        changed: Notify::new(),
    });
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
            s.child_alive = false;
            if let Ok(Some(status)) = s.pty.try_wait() {
                s.emu.set_exit_code(status.exit_code());
            }
            drop(s);
            handle.changed.notify_one();
            break;
        };
        let mut s = handle.session.lock().await;
        s.emu.process(&chunk);
        // Answer any terminal queries the shell/app emitted (DSR/DA/DECRQM) by writing the
        // replies straight back to the PTY — they are host I/O, not screen content.
        let replies = s.emu.take_host_replies();
        if !replies.is_empty() {
            if let Err(e) = s.pty.write_input(&replies) {
                // debug, not warn: a just-exited child makes a failed reply write expected and noisy.
                tracing::debug!(error = %e, "pty host-reply write failed");
            }
        }
        drop(s);
        handle.changed.notify_one();
    }
}

/// Whether [`attach`] spawned a fresh session or reattached to an existing one.
///
/// Lets the server tell the peer it's resuming a running session (mosh-server's `warn_unattached`,
/// mapped to koh's one-detachable-session-per-peer model: there is never a duplicate to warn about,
/// only a resume).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachKind {
    /// A brand-new shell session was spawned for this peer.
    Created,
    /// Reattached to the peer's existing session. `detached_for` is how long it had been detached
    /// (`None` if it wasn't marked detached, e.g. a second overlapping connection).
    Reattached { detached_for: Option<Duration> },
}

/// Get-or-create the detachable session for `peer`. On reattach, clears the detach timer so the
/// reaper won't collect it while the client is back, and reports how long it had been detached.
///
/// `max_sessions` caps the number of distinct live sessions (L-3): reattaching to `peer`'s existing
/// session is always allowed, but creating a NEW session when the store already holds `max_sessions`
/// is refused (returns `Ok(None)`), so a flood of distinct keys can't spawn unbounded shells.
pub async fn attach(
    store: &SessionStore,
    peer: EndpointId,
    shell: Option<&str>,
    scrollback: usize,
    max_sessions: usize,
) -> anyhow::Result<Option<(SharedSession, AttachKind)>> {
    let mut map = store.lock().await;
    if let Some(h) = map.get(&peer) {
        let mut s = h.session.lock().await;
        let detached_for = s.last_detach.map(|t| t.elapsed());
        s.last_detach = None;
        s.attached = s.attached.saturating_add(1);
        drop(s);
        return Ok(Some((h.clone(), AttachKind::Reattached { detached_for })));
    }
    // New peer: enforce the live-session cap before spawning a shell.
    if map.len() >= max_sessions {
        return Ok(None);
    }
    let handle = spawn_session(shell, scrollback)?;
    handle.session.lock().await.attached = 1;
    map.insert(peer, handle.clone());
    Ok(Some((handle, AttachKind::Created)))
}

/// Detach one client from `peer`'s session (the shell keeps running for reattach).
///
/// The detach timer is stamped only when the *last* attached client leaves, so a concurrent
/// same-peer connection detaching can't mark a session the other is still using as reapable.
pub async fn detach(store: &SessionStore, peer: EndpointId) {
    if let Some(h) = store.lock().await.get(&peer) {
        let mut s = h.session.lock().await;
        s.attached = s.attached.saturating_sub(1);
        if s.attached == 0 {
            s.last_detach = Some(Instant::now());
        }
    }
}

/// RAII safety net that releases an attached connection's session if its task unwinds (K-16).
///
/// If the per-connection task **panics** before it can run its explicit [`detach`]/[`reap`], this
/// guard's `Drop` still releases the attach — decrementing `attached` and arming the detach timer —
/// so a panicking task can't leak the session forever. Without it a panic skips the post-`await`
/// cleanup, leaving `attached > 0` and `last_detach == None`, which the reaper (keyed on `!child_alive ||
/// detached_expired`) never collects: a zombie shell + PTY pinned for the server's lifetime.
///
/// A standard RAII Drop-cleans-up-on-unwind discipline. On the normal return paths the task
/// [`disarm`](Self::disarm)s the guard and does the precise cleanup (detach **vs** reap) itself; the
/// guard only fires on an unexpected unwind. `Drop` can't `await`, so it spawns the async detach onto
/// the current runtime (best-effort: a no-op if no runtime is in scope).
#[must_use = "hold the guard for the connection's lifetime, then disarm() on a normal return"]
pub(crate) struct AttachGuard {
    store: SessionStore,
    peer: EndpointId,
    armed: bool,
}

impl AttachGuard {
    /// Arm a guard for a freshly-attached `peer` connection. Hold it across the connection loop.
    pub(crate) fn new(store: SessionStore, peer: EndpointId) -> Self {
        Self {
            store,
            peer,
            armed: true,
        }
    }

    /// Disable the safety net once the connection returned normally and the caller will run the
    /// precise [`detach`]/[`reap`] itself. Consumes the guard so its `Drop` becomes a no-op.
    pub(crate) fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for AttachGuard {
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
        // shell exits (the reaper also reaps on `!child_alive`), so it is not pinned for the server's
        // lifetime. Do NOT "fix" this with per-connection JoinSet panic-observation — that would
        // complicate the accept loop's deliberate spawn-and-forget shape for a moot window.
        let store = self.store.clone();
        let peer = self.peer;
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                detach(&store, peer).await;
                tracing::warn!(
                    %peer,
                    "connection task unwound; released its session attach via the drop guard"
                );
            });
        } else {
            // No runtime in scope (the server is tearing its runtime down): the balancing detach
            // can't be spawned, so this attach is not decremented here. It is NOT a permanent leak —
            // the reaper also collects on `!child_alive`, so the session is reclaimed once the
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
pub async fn reap(store: &SessionStore, peer: EndpointId) {
    let removed = store.lock().await.remove(&peer);
    if let Some(h) = removed {
        teardown(h).await;
    }
}

/// Tear down a session we have just removed from the store.
///
/// If we now hold the **only** reference (the drain task has already ended — typical once the
/// shell has exited), gracefully shut the PTY down: `Pty::shutdown` kills the child and joins both
/// I/O pump threads, so they don't linger as detached threads. The join blocks, so it runs on
/// `spawn_blocking`, never on an async worker. Otherwise some other holder (an attached connection,
/// or the drain task) still owns it, so we just kill the child and let the threads exit when the
/// last reference drops — joining there would mean reaching into shared state we don't own.
async fn teardown(handle: SharedSession) {
    match Arc::try_unwrap(handle) {
        Ok(h) => {
            let Session { pty, .. } = h.session.into_inner();
            tokio::task::spawn_blocking(move || pty.shutdown());
        }
        Err(h) => {
            // Some other holder (an attached connection, or the drain task) still owns the session,
            // so we can't join the pump threads here. Kill the child — log a failed SIGHUP, then
            // force SIGKILL so a SIGHUP-immune child can't keep the reader thread + fds wedged and
            // stop the last `Arc` (hence the `Pty` Drop) from ever running (KOH-10).
            let mut s = h.session.lock().await;
            if let Err(e) = s.pty.kill() {
                tracing::warn!(error = %e, "pty kill during teardown failed");
            }
            s.pty.kill_hard();
        }
    }
}

/// Background sweeper: reap sessions whose shell has exited, or that have been detached longer
/// than `ttl`, every `interval`.
///
/// Runs until the store is dropped. `interval` is injectable (the binary passes [`REAP_INTERVAL`])
/// so tests can drive a sweep without a real multi-second wait. `shutdown` lets the caller stop the
/// reaper cleanly: the loop `select!`s the token against the sleep and returns when cancelled
/// (rather than being `abort()`ed mid-sweep).
pub(crate) async fn run_reaper(
    store: SessionStore,
    ttl: Duration,
    interval: Duration,
    shutdown: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = shutdown.cancelled() => return,
        }
        let mut map = store.lock().await;
        let mut dead = Vec::new();
        for (peer, h) in map.iter() {
            let s = h.session.lock().await;
            let detached_expired = s.last_detach.is_some_and(|t| t.elapsed() >= ttl);
            if !s.child_alive || detached_expired {
                dead.push(*peer);
            }
        }
        let doomed: Vec<SharedSession> = dead.iter().filter_map(|peer| map.remove(peer)).collect();
        drop(map); // release the store lock before tearing down (teardown may lock a session)
        for h in doomed {
            teardown(h).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport_iroh::generate_secret_key;

    #[tokio::test]
    async fn attach_reports_created_then_reattached() {
        // First attach for a peer creates a session; a later attach (after detach) reattaches to
        // the same session and reports how long it was detached — the data the server logs as the
        // mosh-style "resuming your session" notice.
        let store = SessionStore::default();
        let peer = generate_secret_key().public();

        let (h1, kind) = attach(&store, peer, Some("sh"), 0, 64)
            .await
            .expect("first attach")
            .expect("not at capacity");
        assert_eq!(kind, AttachKind::Created, "first attach creates a session");

        detach(&store, peer).await;
        let (h2, kind) = attach(&store, peer, Some("sh"), 0, 64)
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
        let _ = h2.session.lock().await.pty.kill();
    }

    #[tokio::test]
    async fn overlapping_detach_does_not_arm_reaper_until_last_client_leaves() {
        // Two concurrent connections from the same peer share one session. The first detach must
        // NOT stamp last_detach (the other client is still using the shell); only the last detach
        // arms the TTL reaper. Otherwise the reaper could collect the session under an active client.
        let store = SessionStore::default();
        let peer = generate_secret_key().public();

        let (h, _) = attach(&store, peer, Some("sh"), 0, 64)
            .await
            .expect("attach A")
            .expect("not at capacity");
        let (_, _) = attach(&store, peer, Some("sh"), 0, 64)
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

        let _ = h.session.lock().await.pty.kill();
    }

    #[tokio::test]
    async fn attach_guard_releases_the_attach_when_dropped_armed() {
        // K-16: an armed guard dropped without disarm (the panic-unwind case) must release the
        // attach — decrement `attached` to 0 and arm the detach timer — so the reaper can collect
        // the session instead of it leaking with attached>0/last_detach=None forever.
        let store = SessionStore::default();
        let peer = generate_secret_key().public();
        let (h, _) = attach(&store, peer, Some("sh"), 0, 64)
            .await
            .expect("attach")
            .expect("under cap");
        assert_eq!(h.session.lock().await.attached, 1);

        // Simulate a connection task that unwinds before its explicit cleanup: the guard drops armed.
        {
            let _g = AttachGuard::new(store.clone(), peer);
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
        let _ = h.session.lock().await.pty.kill();
    }

    #[tokio::test]
    async fn attach_guard_is_a_noop_once_disarmed() {
        // The normal return path disarms the guard and does its own detach/reap; a disarmed guard
        // must NOT also fire (which would double-decrement the refcount).
        let store = SessionStore::default();
        let peer = generate_secret_key().public();
        let (h, _) = attach(&store, peer, Some("sh"), 0, 64)
            .await
            .expect("attach")
            .expect("under cap");
        assert_eq!(h.session.lock().await.attached, 1);

        AttachGuard::new(store.clone(), peer).disarm();
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
        let _ = h.session.lock().await.pty.kill();
    }

    #[tokio::test]
    async fn attach_enforces_session_cap_but_allows_reattach() {
        // L-3: with a cap of 2, a third DISTINCT peer is refused (Ok(None)) — a flood of keys can't
        // spawn unbounded shells — but an already-present peer can always reattach.
        let store = SessionStore::default();
        let p1 = generate_secret_key().public();
        let p2 = generate_secret_key().public();
        let p3 = generate_secret_key().public();

        let (h1, _) = attach(&store, p1, Some("sh"), 0, 2)
            .await
            .expect("attach p1")
            .expect("under cap");
        let (h2, _) = attach(&store, p2, Some("sh"), 0, 2)
            .await
            .expect("attach p2")
            .expect("under cap");

        // Store is now full (2/2): a brand-new peer is refused.
        let rejected = attach(&store, p3, Some("sh"), 0, 2)
            .await
            .expect("attach p3 ok-result");
        assert!(
            rejected.is_none(),
            "a new peer beyond the cap must be refused"
        );

        // But an existing peer reattaches fine even at capacity.
        detach(&store, p1).await;
        let reattach = attach(&store, p1, Some("sh"), 0, 2)
            .await
            .expect("reattach p1")
            .expect("reattach is allowed at capacity");
        assert!(
            matches!(reattach.1, AttachKind::Reattached { .. }),
            "an existing peer reattaches at capacity, got {:?}",
            reattach.1
        );

        for h in [h1, h2] {
            let _ = h.session.lock().await.pty.kill();
        }
    }

    #[tokio::test]
    async fn reaper_collects_dead_session_at_injected_interval() {
        // Inject a 10ms sweep interval instead of the 5s default, so the reaper's collection of a
        // dead session is observable in a fast, deterministic test.
        let store = SessionStore::default();
        let peer = generate_secret_key().public();

        // A real session whose shell we immediately mark as exited.
        let handle = spawn_session(Some("sh"), 0).expect("spawn session");
        handle.session.lock().await.child_alive = false;
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
}
