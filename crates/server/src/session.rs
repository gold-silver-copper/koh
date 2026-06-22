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
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use anyhow::Context;
use iroh::EndpointId;
use rmosh_terminal::{ServerTerminal, DEFAULT_COLS, DEFAULT_ROWS};
use rmosh_transport_iroh::ratelimit::FailureLimiter;
use rmosh_transport_iroh::MonoClock;
use tokio::sync::{mpsc, Mutex, Notify};
use tokio_util::sync::CancellationToken;

/// Default cadence the reaper sweeps for dead/expired sessions (injectable per call so tests can
/// drive it without a real 5s wait).
pub const REAP_INTERVAL: Duration = Duration::from_secs(5);

/// Shared per-peer auth-failure limiter. A `std::sync::Mutex` (not tokio's) because its ops are
/// synchronous and brief and are never held across an `.await`.
pub type AuthLimiter = Arc<StdMutex<FailureLimiter<EndpointId>>>;

/// A long-lived shell session that survives client disconnects.
pub struct Session {
    pub emu: ServerTerminal,
    pub pty: rmosh_pty::Pty,
    /// False once the shell process has exited (the drain task hit EOF).
    pub child_alive: bool,
    /// When the last client detached (`None` while attached); drives TTL reaping.
    pub last_detach: Option<Instant>,
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
        rmosh_pty::Pty::spawn(rows, cols, shell, "xterm-256color").context("spawning shell")?;
    let handle = Arc::new(SessionHandle {
        session: Mutex::new(Session {
            emu,
            pty,
            child_alive: true,
            last_detach: None,
        }),
        changed: Notify::new(),
    });
    tokio::spawn(drain(handle.clone(), pty_rx));
    Ok(handle)
}

/// Drain PTY output into the emulator for the whole life of the session, pulsing `changed`.
/// Owns `pty_rx` exclusively (it is not `Clone`), so the screen stays current while detached.
async fn drain(handle: SharedSession, mut pty_rx: mpsc::Receiver<Vec<u8>>) {
    loop {
        match pty_rx.recv().await {
            Some(chunk) => {
                let mut s = handle.session.lock().await;
                s.emu.process(&chunk);
                // Answer any terminal queries the shell/app emitted (DSR/DA/DECRQM) by writing
                // the replies straight back to the PTY — they are host I/O, not screen content.
                let replies = s.emu.take_host_replies();
                if !replies.is_empty() {
                    let _ = s.pty.write_input(&replies);
                }
                drop(s);
                handle.changed.notify_one();
            }
            None => {
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
            }
        }
    }
}

/// Get-or-create the detachable session for `peer`. On reattach, clears the detach timer so the
/// reaper won't collect it while the client is back.
pub async fn attach(
    store: &SessionStore,
    peer: EndpointId,
    shell: Option<&str>,
    scrollback: usize,
) -> anyhow::Result<SharedSession> {
    let mut map = store.lock().await;
    if let Some(h) = map.get(&peer) {
        h.session.lock().await.last_detach = None;
        return Ok(h.clone());
    }
    let handle = spawn_session(shell, scrollback)?;
    map.insert(peer, handle.clone());
    Ok(handle)
}

/// Mark `peer`'s session detached (records the time; the shell keeps running for reattach).
pub async fn detach(store: &SessionStore, peer: EndpointId) {
    if let Some(h) = store.lock().await.get(&peer) {
        h.session.lock().await.last_detach = Some(Instant::now());
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
            let _ = h.session.lock().await.pty.kill();
        }
    }
}

/// Background sweeper: reap sessions whose shell has exited, or that have been detached longer
/// than `ttl`, every `interval`. Also piggybacks the auth-failure limiter's GC on each sweep,
/// bounding its keyspace under `--allow-any` (where any number of distinct peers could each leave
/// a stale entry). Runs until the store is dropped. `clock` is the same monotonic clock the accept
/// loop stamps failures with, so the GC's window arithmetic agrees with `check`/`record_failure`.
/// `interval` is injectable (the binary passes [`REAP_INTERVAL`]) so tests can drive a sweep
/// without a real multi-second wait. `shutdown` lets the caller stop the reaper cleanly: the
/// loop `select!`s the token against the sleep and returns when cancelled (rather than being
/// `abort()`ed mid-sweep).
pub async fn run_reaper(
    store: SessionStore,
    ttl: Duration,
    limiter: AuthLimiter,
    clock: MonoClock,
    interval: Duration,
    shutdown: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = shutdown.cancelled() => return,
        }
        // Evict aged-out auth-failure entries (poison unwrap is a panic check, not peer input).
        limiter
            .lock()
            .expect("auth limiter mutex poisoned")
            .gc(clock.now_ms());
        let mut map = store.lock().await;
        let mut dead = Vec::new();
        for (peer, h) in map.iter() {
            let s = h.session.lock().await;
            let detached_expired = s.last_detach.map(|t| t.elapsed() >= ttl).unwrap_or(false);
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
    use rmosh_transport_iroh::generate_secret_key;

    #[tokio::test]
    async fn reaper_collects_dead_session_at_injected_interval() {
        // Inject a 10ms sweep interval instead of the 5s default, so the reaper's collection of a
        // dead session is observable in a fast, deterministic test.
        let store: SessionStore = Default::default();
        let limiter: AuthLimiter = Arc::new(StdMutex::new(FailureLimiter::new(1000, 3)));
        let clock = MonoClock::new();
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
            limiter,
            clock,
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
