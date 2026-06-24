//! The koh server: the per-connection session loop.
//!
//! Reused by the binary and by integration tests (so the full PTY⇄emulator⇄transport path can be
//! exercised over a real iroh connection without the CLI/accept scaffolding).
//!
//! Sessions are **detachable**: the long-lived PTY+emulator lives in [`session::Session`] and
//! survives client disconnects; a per-connection [`run_attached`] loop drives a *fresh*
//! `Transport` against it, so a reconnecting client re-syncs to the current screen.

pub mod audit;
pub mod cli;
pub mod policy;
pub mod session;

pub use cli::{serve, ServeArgs};

use std::time::Duration;

use crate::input::{UserInput, WireEvent};
use crate::ssp::{RecvOutcome, Transport};
use crate::terminal::TerminalScreen;
use crate::transport_iroh::{IrohChannel, MonoClock};
use session::SharedSession;
use tracing::{info, warn};

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
pub struct CursorKeyNormalizer {
    state: Ss3State,
}

impl CursorKeyNormalizer {
    /// Normalize `input` for an app whose application-cursor-keys mode is `app_cursor`, returning
    /// the bytes to feed the PTY.
    pub fn normalize(&mut self, input: &[u8], app_cursor: bool) -> Vec<u8> {
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

/// The server's pure, I/O-free SSP core for one attached connection — the analogue of the client's
/// [`ClientSession`](crate::client). It owns the `Transport`, the DECCKM arrow-key normalizer, and
/// the dirty-snapshot flag, and exposes synchronous step methods (each taking `now: u64`) so the
/// protocol bookkeeping — the echo-ack-gated snapshot decision (S-03), the KOH-05 coalescing handoff,
/// and the shutdown-sentinel handshake — is unit-testable WITHOUT iroh, tokio, or a real PTY.
/// [`run_attached`] is the thin async shell that locks the session, does the I/O, and calls these.
///
/// Unlike `ClientSession`, this core is deliberately **lock-coupled**: the authoritative screen lives
/// in the session `Mutex` (shared with the drain task), so the shell snapshots it under the lock and
/// hands the snapshot in — the core can't own the emulator. That makes the split weaker than the
/// client's, but still lifts every protocol decision out of the async loop where it can be tested.
struct ServerSession {
    transport: Transport<TerminalScreen, UserInput>,
    cursor_keys: CursorKeyNormalizer,
    /// Whether the screen may have changed since the last grid snapshot (S-03).
    dirty: bool,
}

impl ServerSession {
    fn new(now: u64, mtu: usize) -> Self {
        let mut transport = Transport::<TerminalScreen, UserInput>::new(now, mtu);
        transport.set_connected(true);
        Self {
            transport,
            cursor_keys: CursorKeyNormalizer::default(),
            dirty: true, // snapshot on the first pass
        }
    }

    /// Refresh the transport's MTU + RTT from the live channel at the top of each wake.
    fn observe_link(&mut self, mtu: usize, rtt_ms: Option<f64>) {
        self.transport.set_mtu(mtu);
        if let Some(rtt) = rtt_ms {
            self.transport.observe_rtt(rtt);
        }
    }

    /// Whether a fresh grid snapshot must be installed this wake: the screen is dirty OR the echo-ack
    /// advanced (which must ship even with no grid change, else prediction-confirmation timing
    /// breaks). The shell takes the (expensive) snapshot under the session lock only when this is true.
    const fn needs_snapshot(&self, echo_changed: bool) -> bool {
        self.dirty || echo_changed
    }

    /// Install the freshly-taken screen snapshot (present iff [`needs_snapshot`](Self::needs_snapshot)
    /// said so) and clear the dirty flag. A skipped snapshot leaves `current_state` equal to the
    /// still-current screen, so the next `tick` correctly emits acks-only with no missed update.
    fn install_snapshot(&mut self, snapshot: Option<TerminalScreen>) {
        if let Some(screen) = snapshot {
            *self.transport.current_mut() = screen;
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
/// The thin async/I/O shell around [`ServerSession`] (the pure protocol core): it locks the session,
/// does the iroh + PTY I/O, and delegates every protocol decision to the core. Uses a **fresh**
/// core per attach, so the first tick diffs the live screen against the default base and re-syncs the
/// (re)connecting client to the current screen. Crucially, it does **not** kill the PTY on
/// disconnect — it returns [`SessionExit::Detached`] and leaves the shell running for the next reattach.
///
/// Returns `anyhow::Result` for signature stability, but in practice only ever returns `Ok`: a
/// dropped connection is `Ok(Detached)`, a completed shutdown is `Ok(ShellExited)`, and the internal
/// failure paths (PTY write/resize) are logged-and-continued. The `Err` arm at call sites is dead
/// today; it is kept so a future fallible step needn't change the signature.
pub async fn run_attached(
    conn: iroh::endpoint::Connection,
    handle: SharedSession,
) -> anyhow::Result<SessionExit> {
    let channel = IrohChannel::new(conn);
    let clock = MonoClock::new();
    let mut session = ServerSession::new(clock.now_ms(), channel.max_datagram_size());

    loop {
        let now = clock.now_ms();
        session.observe_link(channel.max_datagram_size(), channel.rtt_ms());

        // Snapshot the live screen + read echo-ack timing under the session lock. The snapshot clones
        // the whole vt100 grid + title/icon/clipboard, so the core gates it: take it only when the
        // screen may have changed or the echo-ack advanced (S-03).
        let (echo_wait, child_alive) = {
            let mut s = handle.session.lock().await;
            let echo_changed = s.emu.set_echo_ack(now);
            let snapshot = session
                .needs_snapshot(echo_changed)
                .then(|| s.emu.snapshot());
            session.install_snapshot(snapshot);
            (s.emu.echo_ack_wait_time(now), s.child_alive)
        };
        let sleep_ms = session.wait_ms(now, echo_wait);

        tokio::select! {
            // NOT biased: `changed` can hold a stored permit, which under `biased` would starve
            // client input. A fair select interleaves rendering and input.
            _ = handle.changed.notified() => session.mark_dirty(),

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
                            let app_cursor = s.emu.application_cursor();
                            if let Some(input) = session.drain_input(app_cursor) {
                                // A read-only (observer) session still drains — `drain_input`'s
                                // collapse of `received_states` is a required per-state side effect —
                                // but the client's keystrokes and resizes never reach the PTY: a
                                // `restrict`ed peer can watch the live shell, not drive it.
                                if !s.read_only {
                                    if !input.keys.is_empty() {
                                        if let Err(e) = s.pty.write_input(&input.keys) {
                                            warn!(error = %e, "pty write failed");
                                        }
                                    }
                                    if let Some((rows, cols)) = input.resize {
                                        if let Err(e) = s.pty.resize(rows, cols) {
                                            // A failed TIOCSWINSZ silently diverges the kernel winsize
                                            // from the vt100 grid (full-screen-app corruption with no
                                            // breadcrumb today); warn, but still resize the emulator so
                                            // the screen geometry keeps tracking the client.
                                            warn!(error = %e, rows, cols, "pty resize failed");
                                        }
                                        s.emu.resize(rows, cols);
                                    }
                                }
                                s.emu.register_input_frame(input.frame, now);
                                drop(s);
                                // Applied input may have resized the emulator (a direct grid change
                                // not signaled via `changed`), so re-snapshot next pass.
                                session.mark_dirty();
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

/// Convenience: run a **standalone** (non-detachable) session for one connection.
///
/// Spawns a shell, serves it, and kills it when the connection ends. Used by integration tests and
/// any caller that doesn't need reattach. The binary uses the [`session`] store + [`run_attached`].
pub async fn run_session(
    conn: iroh::endpoint::Connection,
    shell: Option<String>,
    scrollback: usize,
) -> anyhow::Result<()> {
    let handle = session::spawn_session(shell.as_deref(), scrollback, None, false)?;
    let _ = run_attached(conn, handle.clone()).await?;
    let _ = handle.session.lock().await.pty.kill();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{coalesce_drained_input, CursorKeyNormalizer, ServerSession};
    use crate::input::{UserInput, WireEvent};
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

    // --- ServerSession pure-core tests (AR-01): the server's protocol bookkeeping, exercised with no
    //     iroh / tokio / PTY — the deterministic-unit-test bar the client's ClientSession already had.

    #[test]
    fn server_session_snapshot_gating() {
        // The S-03 dirty/echo-ack snapshot decision, isolated from the lock + the real emulator.
        let mut s = ServerSession::new(0, 1200);
        assert!(s.needs_snapshot(false), "the first pass always snapshots");
        s.install_snapshot(Some(TerminalScreen::default()));
        assert!(!s.needs_snapshot(false), "clean after a snapshot");
        assert!(
            s.needs_snapshot(true),
            "an echo-ack advance forces a snapshot even when clean (else confirmations stall)"
        );
        s.mark_dirty();
        assert!(
            s.needs_snapshot(false),
            "a changed-pulse / applied resize re-arms the snapshot"
        );
    }

    #[test]
    fn server_session_shutdown_handshake_progresses() {
        // The shutdown-sentinel handshake progression, without a PTY or a peer.
        let mut s = ServerSession::new(0, 1200);
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

        let mut server = ServerSession::new(0, 1200);
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
}
