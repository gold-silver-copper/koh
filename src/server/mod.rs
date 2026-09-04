//! The koh server: the per-connection session loop.
//!
//! Reused by the binary and by integration tests (so the full PTY⇄emulator⇄transport path can be
//! exercised over a real iroh connection without the CLI/accept scaffolding).
//!
//! Sessions are **detachable**: the long-lived host (a PTY+emulator by default, any
//! [`session::SessionHost`] in general — KH-01) lives in [`session::Session`] and survives client
//! disconnects; a per-connection [`run_attached`] loop drives a *fresh* `Transport` against it, so
//! a reconnecting client re-syncs to the current state.

mod audit;
pub mod cli;
pub mod session;

#[cfg(feature = "cli")]
pub use cli::ServeArgs;
pub use cli::{serve, serve_with, Hosts, ServeConfig};
pub use session::{
    ChangeSignal, ClientId, HostProvider, PtyHost, PtyHosts, SessionHost, SharedHost, SharedSession,
};

use std::time::Duration;

use crate::input::{UserInput, WireEvent};
use crate::ssp::{RecvOutcome, SyncState, Transport};
use crate::transport_iroh::{IrohChannel, MonoClock};
use tracing::info;

/// Why an attached connection loop returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionExit {
    /// The client connection dropped; the session stays alive for reattach.
    Detached,
    /// The shell exited and the shutdown handshake completed; the session should be reaped.
    ShellExited,
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum Ss3State {
    #[default]
    Ground,
    Esc,
    Ss3,
}

/// Rewrites the client's arrow keys to match the remote app's DECCKM mode before they reach the PTY.
///
/// SS3-form cursor keys (`ESC O A..D`) become CSI-form (`ESC [ A..D`) when the app is NOT in
/// application-cursor mode, so arrows behave regardless of the local terminal's mode (a faithful
/// port of mosh's `UserInput::input`). The `ESC` is emitted eagerly and the SS3 state carries
/// across input chunks.
#[derive(Default)]
struct CursorKeyNormalizer {
    state: Ss3State,
}

impl CursorKeyNormalizer {
    /// Normalize `input` for an app whose application-cursor-keys mode is `app_cursor`, returning
    /// the bytes to feed the PTY.
    fn normalize(&mut self, input: &[u8], app_cursor: bool) -> Vec<u8> {
        let mut out = Vec::with_capacity(input.len() + 1);
        for &b in input {
            match self.state {
                Ss3State::Ground => {
                    if b == 0x1b {
                        self.state = Ss3State::Esc;
                    }
                    out.push(b); // ESC is emitted eagerly (mosh)
                }
                Ss3State::Esc => {
                    if b == b'O' {
                        self.state = Ss3State::Ss3; // hold the 'O' pending its final byte
                    } else {
                        self.state = Ss3State::Ground;
                        out.push(b);
                    }
                }
                Ss3State::Ss3 => {
                    self.state = Ss3State::Ground;
                    // ESC was already emitted; complete the sequence, rewriting SS3 -> CSI when the
                    // app isn't in application-cursor mode.
                    out.push(if !app_cursor && (b'A'..=b'D').contains(&b) {
                        b'['
                    } else {
                        b'O'
                    });
                    out.push(b);
                }
            }
        }
        out
    }
}

/// Coalesce a batch of drained client input before it touches the PTY (KOH-05).
///
/// A single datagram set can pack a huge number of events; applying each synchronously — an
/// `ioctl(TIOCSWINSZ)` + SIGWINCH and a `vt100` grid realloc per resize — is a CPU/syscall DoS.
/// Intermediate resizes have no observable effect, so only the LAST geometry is kept (clamped to
/// `[MIN_DIM, MAX_DIM]` before the PTY/vt100 ever see it, H-1 / M-2); keystrokes concatenate in
/// order through the DECCKM normalizer. Pure (given the normalizer + `app_cursor`) so the
/// security-relevant collapse is unit-testable without a real PTY/transport.
fn coalesce_drained_input(
    input_diff: &[WireEvent],
    cursor_keys: &mut CursorKeyNormalizer,
    app_cursor: bool,
) -> (Vec<u8>, Option<(u16, u16)>) {
    let mut keys = Vec::new();
    let mut last_resize: Option<(u16, u16)> = None;
    for w in input_diff {
        match w {
            WireEvent::Keys(b) => keys.extend(cursor_keys.normalize(b, app_cursor)),
            WireEvent::Resize { rows, cols } => {
                last_resize = Some(crate::terminal::clamp_dims(*rows, *cols));
            }
        }
    }
    (keys, last_resize)
}

/// The coalesced client input one `NewState` datagram drained, ready to apply to the PTY/emulator.
struct DrainedInput {
    keys: Vec<u8>,
    resize: Option<(u16, u16)>,
    frame: u64,
}

/// Server-side debounce before a received input frame is considered "echoed" (mosh `ECHO_TIMEOUT`).
pub(crate) const ECHO_TIMEOUT_MS: u64 = 50;

/// The per-connection echo-ack tracker (S-03, KS-02): which of *this* client's input frames the
/// hosted program has had time to reflect. Mosh `Complete::set_echo_ack` / `wait_time`.
///
/// SSP frame numbers are per transport, so this lives in [`ServerSession`] — one per attached
/// connection — never in the host. A shared host with two viewers would otherwise conflate their
/// frame sequences and hand the second viewer an ack for frames it never sent.
#[derive(Debug)]
pub(crate) struct EchoAck {
    /// The newest input frame number whose effects are considered on-screen.
    acked: u64,
    /// Pending `(input_frame_num, arrival_timestamp_ms)`, oldest first.
    input_history: Vec<(u64, u64)>,
    /// Echo debounce (ms): how long after an input frame arrives before it counts as echoed.
    /// Defaults to [`ECHO_TIMEOUT_MS`]; injectable so timing is testable without the wall clock.
    echo_timeout_ms: u64,
}

impl Default for EchoAck {
    fn default() -> Self {
        Self {
            acked: 0,
            input_history: Vec::new(),
            echo_timeout_ms: ECHO_TIMEOUT_MS,
        }
    }
}

impl EchoAck {
    /// A tracker with a custom debounce (ms); tests inject a small value to exercise the promotion
    /// timing deterministically.
    #[cfg(test)]
    pub(crate) fn with_timeout_ms(echo_timeout_ms: u64) -> Self {
        Self {
            echo_timeout_ms,
            ..Self::default()
        }
    }

    /// Record that user-input frame `n` arrived at `now` (ms). The screen has had no time to
    /// reflect it yet; [`set_echo_ack`](Self::set_echo_ack) promotes it after the debounce.
    pub(crate) fn register_input_frame(&mut self, n: u64, now: u64) {
        // Frame numbers only advance; ignore stale/duplicate registrations.
        if self.input_history.last().is_none_or(|(f, _)| n > *f) {
            self.input_history.push((n, now));
        }
    }

    /// Promote `echo_ack` to the newest input frame that arrived at least `echo_timeout_ms`
    /// ago (so the program has had time to echo it). Returns whether it changed.
    pub(crate) fn set_echo_ack(&mut self, now: u64) -> bool {
        let cutoff = now.saturating_sub(self.echo_timeout_ms);
        let mut newest = self.acked;
        for &(frame, ts) in &self.input_history {
            if ts <= cutoff {
                newest = newest.max(frame);
            }
        }
        // Drop history entries strictly older than the new echo_ack (keep it and newer).
        self.input_history.retain(|&(frame, _)| frame >= newest);
        let changed = self.acked != newest;
        self.acked = newest;
        changed
    }

    /// Milliseconds until [`set_echo_ack`](Self::set_echo_ack) could next advance, or
    /// [`NEVER`](crate::ssp::NEVER) if nothing pends.
    pub(crate) fn wait_time(&self, now: u64) -> u64 {
        // The second-oldest pending frame is the next one whose debounce can fire; if there are
        // fewer than two, nothing is waiting. `.get(1)` keeps this panic-free without an index.
        let Some(&(_, arrived)) = self.input_history.get(1) else {
            return crate::ssp::NEVER;
        };
        let fire_at = arrived + self.echo_timeout_ms;
        fire_at.saturating_sub(now)
    }

    /// The current echo-ack value.
    pub(crate) const fn echo_ack(&self) -> u64 {
        self.acked
    }
}

/// The server's pure, I/O-free SSP core for one attached connection — the analogue of the client's
/// [`ClientSession`](crate::client). It owns the `Transport`, the DECCKM arrow-key normalizer, and
/// the dirty-snapshot flag, and exposes synchronous step methods (each taking `now: u64`) so the
/// protocol bookkeeping — the echo-ack-gated snapshot decision (S-03), the KOH-05 coalescing handoff,
/// and the shutdown-sentinel handshake — is unit-testable WITHOUT iroh, tokio, or a real PTY.
/// [`run_attached`] is the thin async shell that locks the session, does the I/O, and calls these.
///
/// Unlike `ClientSession`, this core is deliberately **lock-coupled**: the authoritative state lives
/// in the session `Mutex` (shared with the host's own tasks), so the shell snapshots it under the
/// lock and hands the snapshot in — the core can't own the host. That makes the split weaker than
/// the client's, but still lifts every protocol decision out of the async loop where it can be
/// tested. Generic over the synced state `S` (KH-01): nothing here knows it is a terminal.
struct ServerSession<S: SyncState> {
    transport: Transport<S, UserInput>,
    cursor_keys: CursorKeyNormalizer,
    /// This connection's echo-ack tracker (KS-02).
    echo: EchoAck,
    /// Whether the screen may have changed since the last grid snapshot (S-03).
    dirty: bool,
    /// Whether this connection has installed the terminal host's final snapshot.
    terminal_snapshot_taken: bool,
}

impl<S: SyncState> ServerSession<S> {
    fn new(now: u64, mtu: usize) -> Self {
        let mut transport = Transport::<S, UserInput>::new(now, mtu);
        transport.set_connected(true);
        Self {
            transport,
            cursor_keys: CursorKeyNormalizer::default(),
            echo: EchoAck::default(),
            dirty: true, // snapshot on the first pass
            terminal_snapshot_taken: false,
        }
    }

    /// Promote this connection's echo-ack at `now`; returns whether it advanced (S-03, KS-02).
    fn set_echo_ack(&mut self, now: u64) -> bool {
        self.echo.set_echo_ack(now)
    }

    /// This connection's current echo-ack, to stamp onto the snapshot it ships.
    const fn echo_ack(&self) -> u64 {
        self.echo.echo_ack()
    }

    /// Milliseconds until the echo-ack could next advance.
    fn echo_ack_wait_time(&self, now: u64) -> u64 {
        self.echo.wait_time(now)
    }

    /// Record that this client's input frame `frame` arrived at `now`.
    fn register_input_frame(&mut self, frame: u64, now: u64) {
        self.echo.register_input_frame(frame, now);
    }

    /// Refresh the transport's MTU + RTT from the live channel at the top of each wake.
    fn observe_link(&mut self, mtu: usize, rtt_ms: Option<f64>) {
        self.transport.set_mtu(mtu);
        if let Some(rtt) = rtt_ms {
            self.transport.observe_rtt(rtt);
        }
    }

    /// Whether a fresh grid snapshot must be installed this wake: the screen is dirty, the echo-ack
    /// advanced, or the host is terminal. The final case is intentionally per connection: a shared
    /// host cannot know which independent transports have consumed its final state, so every clean
    /// viewer takes one authoritative snapshot before beginning its shutdown handshake.
    const fn needs_snapshot(&self, echo_changed: bool, child_alive: bool) -> bool {
        self.dirty || echo_changed || (!child_alive && !self.terminal_snapshot_taken)
    }

    /// Install the freshly-taken screen snapshot (present iff [`needs_snapshot`](Self::needs_snapshot)
    /// said so) and clear the dirty flag. A skipped snapshot leaves `current_state` equal to the
    /// still-current screen, so the next `tick` correctly emits acks-only with no missed update.
    fn install_snapshot(&mut self, snapshot: Option<S>, child_alive: bool) {
        if let Some(state) = snapshot {
            *self.transport.current_mut() = state;
            if !child_alive {
                self.terminal_snapshot_taken = true;
            }
        }
        self.dirty = false;
    }

    /// The next wake deadline (ms): the transport's own send/ack timer, the echo-ack debounce, 1s cap.
    fn wait_ms(&mut self, now: u64, echo_wait: u64) -> u64 {
        self.transport.wait_time(now).min(echo_wait).min(1000)
    }

    /// Mark the screen possibly-changed — a `changed` pulse, or applied input that resized the
    /// emulator directly (a grid change not signaled through `changed`).
    fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    /// Feed one inbound datagram into the transport; returns whether it produced a new in-order state.
    /// Pure transport work — the shell calls this OUTSIDE the session lock.
    fn recv(&mut self, now: u64, bytes: &[u8]) -> RecvOutcome {
        self.transport.recv(now, bytes)
    }

    /// Drain the newly-received client input (after a `recv` returning `NewState`) and coalesce it for
    /// the PTY (KOH-05). Always calls `get_remote_diff` — whose collapse of `received_states` is a
    /// required side effect on every new state — then returns the bytes/resize to apply, or `None`
    /// when the new state carried no input. `app_cursor` is read under the lock by the shell (it is
    /// driven by the shell's DECCKM output, so it can't change from client input mid-drain).
    fn drain_input(&mut self, app_cursor: bool) -> Option<DrainedInput> {
        let diff = self.transport.get_remote_diff();
        if diff.is_empty() {
            return None;
        }
        let frame = self.transport.remote_num();
        let (keys, resize) = coalesce_drained_input(&diff, &mut self.cursor_keys, app_cursor);
        Some(DrainedInput {
            keys,
            resize,
            frame,
        })
    }

    /// Advance the shutdown handshake (begin it once the shell has exited) + timers, and produce this
    /// wake's outgoing datagrams.
    fn tick(&mut self, now: u64, child_alive: bool) -> Vec<Vec<u8>> {
        if !child_alive && !self.transport.shutdown_in_progress() {
            self.transport.start_shutdown(now);
        }
        self.transport.tick(now)
    }

    /// Whether the shutdown handshake has completed (peer acked the sentinel, or it timed out) so the
    /// session may be reaped.
    fn shutdown_complete(&self, now: u64) -> bool {
        self.transport.shutdown_in_progress()
            && (self.transport.shutdown_acknowledged()
                || self.transport.shutdown_ack_timed_out(now))
    }
}

/// Drive a client connection against an existing (shared, detachable) [`session::Session`].
///
/// The thin async/I/O shell around `ServerSession` (the pure protocol core): it locks the session,
/// does the iroh + host I/O, and delegates every protocol decision to the core. Uses a **fresh**
/// core per attach, so the first tick diffs the live state against the default base and re-syncs the
/// (re)connecting client to the current state. Crucially, it does **not** kill the host on
/// disconnect — it returns [`SessionExit::Detached`] and leaves it running for the next reattach.
/// `client` identifies this connection to the host (KH-01, KS-01).
///
/// Returns `anyhow::Result` for signature stability, but in practice only ever returns `Ok`: a
/// dropped connection is `Ok(Detached)`, a completed shutdown is `Ok(ShellExited)`, and the internal
/// failure paths (PTY write/resize) are logged-and-continued inside the host. The `Err` arm at call
/// sites is dead today; it is kept so a future fallible step needn't change the signature.
pub async fn run_attached<H: SessionHost>(
    conn: iroh::endpoint::Connection,
    handle: SharedSession<H>,
    client: ClientId,
) -> anyhow::Result<SessionExit> {
    let channel = IrohChannel::new(conn);
    let clock = MonoClock::new();
    let mut session = ServerSession::<H::State>::new(clock.now_ms(), channel.max_datagram_size());
    // This connection's view of the host's change signal (KS-03). Every attached loop has its
    // own receiver, so one pulse wakes all of them.
    let mut changed = handle.changed.subscribe();

    loop {
        let now = clock.now_ms();
        session.observe_link(channel.max_datagram_size(), channel.rtt_ms());

        // Promote this connection's echo-ack (KS-02: per connection, not per host), then snapshot
        // the live state under the session lock. The snapshot clones the whole vt100 grid +
        // title/icon/clipboard, so the core gates it: take it only when the state may have changed
        // or the echo-ack advanced (S-03). The ack is stamped onto the snapshot outside the lock.
        let echo_changed = session.set_echo_ack(now);
        let child_alive = {
            let initially_dirty = session.needs_snapshot(echo_changed, true);
            if initially_dirty {
                // Mark the change signal seen BEFORE snapshotting: a pulse that lands after this
                // point (from a change this snapshot may or may not include) re-fires `changed()`
                // below and costs at most one redundant snapshot. Marking it after the snapshot
                // could swallow a pulse for a change the snapshot missed.
                let _ = changed.borrow_and_update();
            }
            let mut s = handle.session.lock().await;
            let alive_before_snapshot = s.host.alive();
            let take = session.needs_snapshot(echo_changed, alive_before_snapshot);
            if take && !initially_dirty {
                // A terminal host forces a final snapshot even for a connection that did not yet
                // observe the shared change pulse. Mark that pulse seen for this receiver before
                // taking the state, matching the normal dirty-snapshot ordering above.
                let _ = changed.borrow_and_update();
            }
            let mut snapshot = take.then(|| s.host.snapshot());
            let alive = s.host.alive();
            drop(s);
            if let Some(state) = snapshot.as_mut() {
                H::stamp_echo_ack(state, session.echo_ack());
            }
            session.install_snapshot(snapshot, alive);
            alive
        };
        let sleep_ms = session.wait_ms(now, session.echo_ack_wait_time(now));

        tokio::select! {
            // NOT biased: `changed` may already be pending (a pulse since the last snapshot), which
            // under `biased` would starve client input. A fair select interleaves rendering and
            // input. `watch` remembers the last seen version per receiver, so a pulse that landed
            // between the snapshot above and this wait resolves immediately — never lost (KS-03).
            _ = changed.changed() => session.mark_dirty(),

            // Cancel-safety: when `changed` (or the timer) fires first, this in-flight `recv()`
            // future is dropped — sound only because the pinned `iroh = "1.0.0"`'s `read_datagram`
            // is cancel-safe (a dropped future loses no buffered datagram). This loop drops it far
            // more often than the client (on every screen change, not just a timer tick), so any
            // iroh bump must re-verify cancel-safety here too (see `client::drive_connection`).
            dg = channel.recv() => {
                match dg {
                    Ok(bytes) => {
                        let now = clock.now_ms();
                        // recv() is pure transport — outside the lock. Drain + PTY apply happen under
                        // the lock (which also guards `application_cursor`).
                        if session.recv(now, &bytes) == RecvOutcome::NewState {
                            let mut s = handle.session.lock().await;
                            let app_cursor = s.host.application_cursor();
                            if let Some(input) = session.drain_input(app_cursor) {
                                if !input.keys.is_empty() {
                                    s.host.input(&input.keys);
                                }
                                let resized = input.resize.is_some();
                                if let Some((rows, cols)) = input.resize {
                                    s.host.resize(client, rows, cols);
                                }
                                drop(s);
                                session.register_input_frame(input.frame, now);
                                // Only a resize mutates the emulator grid directly (a change not
                                // signaled through `changed`), so re-snapshot next pass only then.
                                // Keystroke-driven changes arrive via the drain task's `changed` pulse
                                // (which sets `dirty` through the select arm above), so an input frame
                                // that didn't resize needs no forced snapshot.
                                if resized {
                                    session.mark_dirty();
                                }
                            }
                        }
                    }
                    Err(e) => {
                        info!(reason = %e, "connection closed by peer (detaching)");
                        channel.close(0, b"client detached");
                        return Ok(SessionExit::Detached);
                    }
                }
            }

            _ = tokio::time::sleep(Duration::from_millis(sleep_ms)) => {}
        }

        let now = clock.now_ms();
        for datagram in session.tick(now, child_alive) {
            channel.send(&datagram);
        }
        if session.shutdown_complete(now) {
            channel.close(0, b"session ended");
            return Ok(SessionExit::ShellExited);
        }
    }
}

/// Convenience: run a **standalone** (non-detachable) PTY session for one connection.
///
/// Spawns a shell, serves it, and kills it when the connection ends. Used by integration tests and
/// any caller that doesn't need reattach. The binary uses the [`session`] store + [`run_attached`].
pub async fn run_session(
    conn: iroh::endpoint::Connection,
    command: &[String],
    scrollback: usize,
) -> anyhow::Result<()> {
    let handle = session::spawn_session(command, scrollback)?;
    run_session_with(conn, handle).await
}

/// Run a **standalone** (non-detachable) session over any host for one connection: serve it,
/// then [`SessionHost::kill`] it when the connection ends (KH-01).
pub async fn run_session_with<H: SessionHost>(
    conn: iroh::endpoint::Connection,
    handle: SharedSession<H>,
) -> anyhow::Result<()> {
    let client = ClientId::next();
    let _ = run_attached(conn, handle.clone(), client).await?;
    let mut s = handle.session.lock().await;
    s.host.client_detached(client);
    s.host.kill();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{coalesce_drained_input, CursorKeyNormalizer, EchoAck, ServerSession};
    use crate::input::{UserInput, WireEvent};
    use crate::ssp::testkit::GridState;
    use crate::ssp::{RecvOutcome, Transport};
    use crate::terminal::TerminalScreen;

    /// Feed `chunks` through one normalizer at the given app-cursor mode, return the PTY bytes.
    fn norm(chunks: &[&[u8]], app_cursor: bool) -> Vec<u8> {
        let mut n = CursorKeyNormalizer::default();
        let mut out = Vec::new();
        for c in chunks {
            out.extend(n.normalize(c, app_cursor));
        }
        out
    }

    #[test]
    fn ss3_arrows_rewrite_to_csi_when_not_in_application_cursor_mode() {
        // ESC O A..D  ->  ESC [ A..D  (the app expects ANSI cursor keys).
        assert_eq!(norm(&[b"\x1bOA"], false), b"\x1b[A");
        assert_eq!(norm(&[b"\x1bOD"], false), b"\x1b[D");
    }

    #[test]
    fn ss3_arrows_preserved_in_application_cursor_mode() {
        assert_eq!(norm(&[b"\x1bOA"], true), b"\x1bOA");
    }

    #[test]
    fn csi_arrows_and_plain_bytes_pass_through() {
        assert_eq!(norm(&[b"\x1b[A"], false), b"\x1b[A");
        assert_eq!(norm(&[b"ls\r"], false), b"ls\r");
        // A bare ESC then a normal byte (e.g. vim's Escape) is untouched.
        assert_eq!(norm(&[b"\x1bi"], false), b"\x1bi");
    }

    #[test]
    fn ss3_sequence_split_across_chunks_normalizes() {
        // The SS3 state carries across input chunks.
        assert_eq!(norm(&[b"\x1b", b"O", b"A"], false), b"\x1b[A");
        assert_eq!(norm(&[b"\x1b", b"[", b"A"], false), b"\x1b[A");
    }

    #[test]
    fn coalesce_keeps_only_the_last_resize_and_concatenates_keys() {
        // KOH-05: a batch with several resizes collapses to ONLY the last geometry (clamped), while
        // keystrokes concatenate in order — the CPU/syscall-DoS mitigation, now unit-testable.
        let mut norm = CursorKeyNormalizer::default();
        let diff = vec![
            WireEvent::Keys(b"ab".to_vec()),
            WireEvent::Resize { rows: 10, cols: 20 },
            WireEvent::Keys(b"cd".to_vec()),
            WireEvent::Resize { rows: 30, cols: 40 },
            WireEvent::Resize {
                rows: 65000,
                cols: 1,
            }, // only this one survives, and it is clamped
            WireEvent::Keys(b"ef".to_vec()),
        ];
        let (keys, last_resize) = coalesce_drained_input(&diff, &mut norm, false);
        assert_eq!(keys, b"abcdef", "keystrokes concatenate in order");
        assert_eq!(
            last_resize,
            Some(crate::terminal::clamp_dims(65000, 1)),
            "only the final resize survives, clamped to [MIN_DIM, MAX_DIM]"
        );
    }

    #[test]
    fn coalesce_with_no_resize_returns_none() {
        let mut norm = CursorKeyNormalizer::default();
        let diff = vec![WireEvent::Keys(b"x".to_vec())];
        let (keys, last_resize) = coalesce_drained_input(&diff, &mut norm, false);
        assert_eq!(keys, b"x");
        assert!(last_resize.is_none(), "no resize event -> None");
    }

    // --- EchoAck (S-03, KS-02): the per-connection echo-ack debounce, moved here from the emulator.

    #[test]
    fn echo_ack_debounces() {
        let mut t = EchoAck::default();
        t.register_input_frame(5, 1000);
        // Too soon: nothing within the debounce window.
        assert!(!t.set_echo_ack(1010));
        assert_eq!(t.echo_ack(), 0);
        // After 50ms the frame is considered echoed.
        assert!(t.set_echo_ack(1050));
        assert_eq!(t.echo_ack(), 5);
    }

    #[test]
    fn echo_ack_honors_injected_timeout() {
        // With a 10ms debounce (not the 50ms default), a frame is echoed after 10ms, not 50 — a
        // deterministic timing assertion only possible because the timeout is injectable.
        let mut t = EchoAck::with_timeout_ms(10);
        t.register_input_frame(5, 1000);
        assert!(
            !t.set_echo_ack(1005),
            "still inside the injected 10ms window"
        );
        assert_eq!(t.echo_ack(), 0);
        assert!(t.set_echo_ack(1011), "past the injected 10ms window");
        assert_eq!(t.echo_ack(), 5);
        // The default (50ms) would not have promoted at 1011.
        let mut d = EchoAck::default();
        d.register_input_frame(5, 1000);
        assert!(
            !d.set_echo_ack(1011),
            "the 50ms default has not elapsed yet"
        );
    }

    #[test]
    fn echo_ack_is_monotonic_and_takes_newest() {
        let mut t = EchoAck::default();
        t.register_input_frame(3, 1000);
        t.register_input_frame(7, 1005);
        t.set_echo_ack(1100); // both older than 50ms -> newest = 7
        assert_eq!(t.echo_ack(), 7);
    }

    #[test]
    fn echo_ack_wait_time_points_at_the_second_pending_frame() {
        let mut t = EchoAck::default();
        assert_eq!(t.wait_time(0), crate::ssp::NEVER, "nothing pending");
        t.register_input_frame(1, 1000);
        assert_eq!(
            t.wait_time(1000),
            crate::ssp::NEVER,
            "one frame: nothing waits behind it"
        );
        t.register_input_frame(2, 1020);
        assert_eq!(t.wait_time(1030), 40, "the second frame fires at 1070");
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(128))]

        /// KS-02: two connections' trackers fed interleaved frame sequences never influence each
        /// other — each ack is bounded by the frames *that* connection registered.
        #[test]
        fn echo_ack_trackers_are_independent_per_connection(
            ops in proptest::collection::vec((proptest::prelude::any::<bool>(), 1u64..1000, 0u64..10_000), 1..64),
        ) {
            let mut a = EchoAck::with_timeout_ms(10);
            let mut b = EchoAck::with_timeout_ms(10);
            let (mut max_a, mut max_b) = (0u64, 0u64);
            for (to_a, frame, now) in ops {
                if to_a {
                    a.register_input_frame(frame, now);
                    max_a = max_a.max(frame);
                } else {
                    b.register_input_frame(frame, now);
                    max_b = max_b.max(frame);
                }
                a.set_echo_ack(now.saturating_add(100));
                b.set_echo_ack(now.saturating_add(100));
                proptest::prop_assert!(a.echo_ack() <= max_a, "A acked a frame it never saw");
                proptest::prop_assert!(b.echo_ack() <= max_b, "B acked a frame it never saw");
            }
        }
    }

    // --- ServerSession pure-core tests (AR-01): the server's protocol bookkeeping, exercised with no
    //     iroh / tokio / PTY — the deterministic-unit-test bar the client's ClientSession already had.

    #[test]
    fn server_session_snapshot_gating() {
        // The S-03 dirty/echo-ack snapshot decision, isolated from the lock + the real emulator —
        // over a non-terminal state (KH-01): the core is state-agnostic.
        let mut s = ServerSession::<GridState>::new(0, 1200);
        assert!(
            s.needs_snapshot(false, true),
            "the first pass always snapshots"
        );
        s.install_snapshot(Some(GridState::default()), true);
        assert!(
            !s.needs_snapshot(false, true),
            "clean live host skips a snapshot"
        );
        assert!(
            s.needs_snapshot(true, true),
            "an echo-ack advance forces a snapshot even when clean (else confirmations stall)"
        );
        assert!(
            s.needs_snapshot(false, false),
            "every clean connection snapshots terminal host state before shutdown"
        );
        s.install_snapshot(Some(GridState::default()), false);
        assert!(
            !s.needs_snapshot(false, false),
            "a connection does not repeatedly clone terminal state during shutdown retries"
        );
        s.mark_dirty();
        assert!(
            s.needs_snapshot(false, true),
            "a changed-pulse / applied resize re-arms the snapshot"
        );
    }

    #[test]
    fn server_session_shutdown_handshake_progresses() {
        // The shutdown-sentinel handshake progression, without a PTY or a peer (KH-01: over a
        // non-terminal state).
        let mut s = ServerSession::<GridState>::new(0, 1200);
        let _ = s.tick(0, true); // child alive -> no shutdown started
        assert!(!s.shutdown_complete(0));
        let _ = s.tick(10, false); // child exited -> begin the shutdown handshake
        assert!(
            !s.shutdown_complete(10),
            "shutdown just started: neither acked nor timed out yet"
        );
        assert!(
            s.shutdown_complete(10_000_000),
            "far in the future the unacked shutdown times out -> reapable"
        );
    }

    #[test]
    fn server_session_drains_coalesced_input_from_a_real_datagram() {
        // Exercise recv + drain_input over a genuine wire datagram authored by a client-side
        // Transport — the KOH-05 coalescing handoff, with no iroh/PTY. The client logs keys then two
        // resizes; the server must drain the concatenated keys and ONLY the last (clamped) resize.
        let mut client = Transport::<UserInput, TerminalScreen>::new(0, 1200);
        client.set_connected(true);
        client.current_mut().push_bytes(b"ls\r");
        client.current_mut().push_resize(10, 20);
        client.current_mut().push_resize(30, 40);
        // Tick well past the send mindelay so the queued input is actually transmitted.
        let datagrams = client.tick(1000);
        assert!(
            !datagrams.is_empty(),
            "the client transmits its queued input"
        );

        let mut server = ServerSession::<TerminalScreen>::new(0, 1200);
        let mut drained = None;
        for dg in &datagrams {
            if server.recv(1000, dg) == RecvOutcome::NewState {
                drained = server.drain_input(false);
            }
        }
        let input = drained.expect("the server drained the client's input");
        assert_eq!(
            input.keys, b"ls\r",
            "keystrokes concatenate in order through the normalizer"
        );
        assert_eq!(
            input.resize,
            Some((30, 40)),
            "KOH-05: only the final resize survives (clamped)"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_session_over_a_scripted_host_delivers_frames_and_clamped_resizes() {
        // KH-01: the generic loop feeds a non-PTY host — `resize` gets the clamped geometry with
        // this connection's id, `input` gets the keys, and the client's frame 1 comes back as
        // the echo-ack the loop stamped (KS-02).
        use crate::server::session::test_host::{HostCall, ScriptedHost};
        use crate::server::session::SessionHandle;
        use crate::transport_iroh::{
            bind_endpoint_local, generate_secret_key, loopback_addr, IrohChannel, MonoClock, ALPN,
        };
        let server_ep = bind_endpoint_local(generate_secret_key(), true)
            .await
            .expect("bind");
        let addr = loopback_addr(&server_ep);
        let handle = SessionHandle::new(ScriptedHost::new());
        let h2 = handle.clone();
        let accept = tokio::spawn(async move {
            if let Some(incoming) = server_ep.accept().await {
                if let Ok(conn) = incoming.await {
                    let _ = super::run_session_with(conn, h2).await;
                }
            }
        });
        let client_ep = bind_endpoint_local(generate_secret_key(), false)
            .await
            .expect("bind client");
        let chan = IrohChannel::new(client_ep.connect(addr, ALPN).await.expect("connect"));
        let clock = MonoClock::new();
        let mut t = Transport::<UserInput, GridState>::new(clock.now_ms(), 1200);
        t.set_connected(true);
        t.observe_rtt(10.0);
        t.current_mut().push_resize(65000, 1);
        t.current_mut().push_bytes(b"xy");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            for dg in t.tick(clock.now_ms()) {
                chan.send(&dg);
            }
            tokio::select! {
                r = chan.recv() => { if let Ok(b) = r { t.recv(clock.now_ms(), &b); } }
                () = tokio::time::sleep(std::time::Duration::from_millis(5)) => {}
            }
            // Wait for the input AND its echo-ack (the ack ships after the 50 ms debounce).
            if t.remote_state().contents().contains("xy") && t.remote_state().echo_ack >= 1 {
                break;
            }
        }
        assert!(
            t.remote_state().contents().contains("xy"),
            "input reached the host"
        );
        chan.close(0, b"done");
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), accept).await;
        let s = handle.session.lock().await;
        let calls = &s.host.calls;
        assert!(
            calls.iter().any(|c| matches!(c, HostCall::Resize(_, r, cc) if (*r, *cc) == crate::terminal::clamp_dims(65000, 1))),
            "resize arrives clamped: {calls:?}"
        );
        assert_eq!(
            t.remote_state().echo_ack,
            1,
            "the loop's own echo-ack for frame 1 is stamped onto the snapshot (KS-02)"
        );
        assert!(
            calls.iter().any(|c| matches!(c, HostCall::Detached(_))),
            "the connection's detach reaches the host: {calls:?}"
        );
        assert!(
            calls.contains(&HostCall::Kill),
            "run_session_with kills the host at the end"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[expect(
        clippy::items_after_statements,
        reason = "the pump helper reads best next to the viewers it drives"
    )]
    async fn echo_ack_is_tracked_per_connection_so_a_second_viewer_sees_only_its_own_frames() {
        // KS-02: two clients on ONE shared ScriptedHost. A sends many frames, B sends one. B's
        // snapshots must carry B's own ack (never A's much larger frame number), and A's must
        // carry A's — the bug this pins was a host-global echo-ack that handed B `echo_ack = 40`.
        use crate::server::session::test_host::ScriptedHost;
        use crate::server::session::{ClientId, SessionHandle};
        use crate::transport_iroh::{
            bind_endpoint_local, generate_secret_key, loopback_addr, IrohChannel, MonoClock, ALPN,
        };
        let server_ep = bind_endpoint_local(generate_secret_key(), true)
            .await
            .expect("bind");
        let addr = loopback_addr(&server_ep);
        let handle = SessionHandle::new(ScriptedHost::new());
        let h2 = handle.clone();
        let accept = tokio::spawn(async move {
            while let Some(incoming) = server_ep.accept().await {
                let h = h2.clone();
                tokio::spawn(async move {
                    if let Ok(conn) = incoming.await {
                        let _ = super::run_attached(conn, h, ClientId::next()).await;
                    }
                });
            }
        });
        let clock = MonoClock::new();
        let mut viewers = Vec::new();
        for _ in 0..2 {
            let ep = bind_endpoint_local(generate_secret_key(), false)
                .await
                .expect("bind client");
            let chan = IrohChannel::new(ep.connect(addr.clone(), ALPN).await.expect("connect"));
            let mut t = Transport::<UserInput, GridState>::new(clock.now_ms(), 1200);
            t.set_connected(true);
            t.observe_rtt(10.0);
            viewers.push((chan, t, ep));
        }
        // Pump both viewers for `ms`, asserting the per-connection invariant on every frame.
        async fn pump(
            viewers: &mut [(IrohChannel, Transport<UserInput, GridState>, iroh::Endpoint)],
            clock: &MonoClock,
            ms: u64,
        ) {
            let deadline = std::time::Instant::now() + std::time::Duration::from_millis(ms);
            while std::time::Instant::now() < deadline {
                for (chan, t, _) in viewers.iter_mut() {
                    for dg in t.tick(clock.now_ms()) {
                        chan.send(&dg);
                    }
                    if let Ok(Ok(b)) =
                        tokio::time::timeout(std::time::Duration::from_millis(2), chan.recv()).await
                    {
                        t.recv(clock.now_ms(), &b);
                    }
                    assert!(
                        t.remote_state().echo_ack <= t.newest_sent_num(),
                        "a viewer was acked for a frame it never sent: ack {} > sent {}",
                        t.remote_state().echo_ack,
                        t.newest_sent_num()
                    );
                }
            }
        }
        // A types 30 separate frames.
        for _ in 0..30 {
            viewers[0].1.current_mut().push_bytes(b"a");
            pump(&mut viewers, &clock, 40).await;
        }
        // B types once.
        viewers[1].1.current_mut().push_bytes(b"b");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            pump(&mut viewers, &clock, 50).await;
            let b_done = viewers[1].1.remote_state().echo_ack >= 1;
            let a_done = viewers[0].1.remote_state().echo_ack >= 30;
            if a_done && b_done {
                break;
            }
        }
        let (a_ack, a_sent) = (
            viewers[0].1.remote_state().echo_ack,
            viewers[0].1.newest_sent_num(),
        );
        let (b_ack, b_sent) = (
            viewers[1].1.remote_state().echo_ack,
            viewers[1].1.newest_sent_num(),
        );
        assert!(
            a_ack >= 30 && a_ack <= a_sent,
            "A's ack covers A's 30 frames: ack {a_ack}, sent {a_sent}"
        );
        assert!(
            b_ack >= 1 && b_ack <= b_sent,
            "B's ack covers B's one frame: ack {b_ack}, sent {b_sent}"
        );
        assert!(
            b_ack < 30,
            "B was handed A's ack ({b_ack}): the echo-ack leaked across connections"
        );
        for (chan, _, _) in &viewers {
            chan.close(0, b"done");
        }
        accept.abort();
    }
}
