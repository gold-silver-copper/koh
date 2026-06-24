//! The koh server: the per-connection session loop.
//!
//! Reused by the binary and by integration tests (so the full PTY⇄emulator⇄transport path can be
//! exercised over a real iroh connection without the CLI/accept scaffolding).
//!
//! Sessions are **detachable**: the long-lived PTY+emulator lives in [`session::Session`] and
//! survives client disconnects; a per-connection [`run_attached`] loop drives a *fresh*
//! `Transport` against it, so a reconnecting client re-syncs to the current screen.

pub mod cli;
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

/// Drive a client connection against an existing (shared, detachable) [`session::Session`].
///
/// Uses a **fresh** `Transport<TerminalScreen, UserInput>` per attach, so the first tick diffs
/// the live screen against the default base and re-syncs the (re)connecting client to the
/// current screen. Crucially, it does **not** kill the PTY on disconnect — it returns
/// [`SessionExit::Detached`] and leaves the shell running for the next reattach.
pub async fn run_attached(
    conn: iroh::endpoint::Connection,
    handle: SharedSession,
) -> anyhow::Result<SessionExit> {
    let channel = IrohChannel::new(conn);
    let clock = MonoClock::new();
    let mut transport =
        Transport::<TerminalScreen, UserInput>::new(clock.now_ms(), channel.max_datagram_size());
    transport.set_connected(true);
    // Normalizes the client's arrow keys to the app's DECCKM mode before they reach the PTY.
    let mut cursor_keys = CursorKeyNormalizer::default();
    // Whether the screen may have changed since the last grid snapshot (S-03). Snapshot on the
    // first pass, then only after a `changed` pulse / applied input or an echo-ack advance — so an
    // idle/timer wake doesn't clone the whole vt100 grid for nothing.
    let mut dirty = true;

    loop {
        let now = clock.now_ms();
        transport.set_mtu(channel.max_datagram_size());
        if let Some(rtt) = channel.rtt_ms() {
            transport.observe_rtt(rtt);
        }

        // Snapshot the live screen + echo-ack timing under the session lock. The snapshot clones the
        // whole vt100 grid + title/icon/clipboard, so skip it when nothing changed since the last
        // wake (S-03): a skipped snapshot leaves `current_state` equal to the still-current screen,
        // so `tick` correctly emits acks-only with no missed update.
        let (echo_wait, child_alive) = {
            let mut s = handle.session.lock().await;
            // set_echo_ack advances the echo-ack on a debounce even with no screen change; its
            // return reports whether it changed. OR it in — else we'd stop shipping echo-ack
            // confirmations and break the client's prediction-confirmation timing.
            let echo_changed = s.emu.set_echo_ack(now);
            if dirty || echo_changed {
                *transport.current_mut() = s.emu.snapshot();
            }
            (s.emu.echo_ack_wait_time(now), s.child_alive)
        };
        dirty = false;
        let wait = transport.wait_time(now);
        let sleep_ms = wait.min(echo_wait).min(1000);

        tokio::select! {
            // NOT biased: `changed` can hold a stored permit, which under `biased` would starve
            // client input. A fair select interleaves rendering and input.
            // Screen changed: re-snapshot on the next pass.
            _ = handle.changed.notified() => dirty = true,

            // Cancel-safety: when `changed` (or the timer) fires first, this in-flight `recv()`
            // future is dropped — sound only because the pinned `iroh = "1.0.0"`'s `read_datagram`
            // is cancel-safe (a dropped future loses no buffered datagram). This loop drops it far
            // more often than the client (on every screen change, not just a timer tick), so any
            // iroh bump must re-verify cancel-safety here too (see `client::drive_connection`).
            dg = channel.recv() => {
                match dg {
                    Ok(bytes) => {
                        let now = clock.now_ms();
                        if transport.recv(now, &bytes) == RecvOutcome::NewState {
                            let input_diff = transport.get_remote_diff();
                            if !input_diff.is_empty() {
                                let frame = transport.remote_num();
                                let mut s = handle.session.lock().await;
                                // Coalesce the drained input before touching the PTY (KOH-05; see
                                // `coalesce_drained_input`). `application_cursor` can't change from
                                // client input — it is driven by the shell's DECCKM output, processed
                                // under this same lock — so it is read once.
                                let app_cursor = s.emu.application_cursor();
                                let (keys, last_resize) =
                                    coalesce_drained_input(&input_diff, &mut cursor_keys, app_cursor);
                                if !keys.is_empty() {
                                    if let Err(e) = s.pty.write_input(&keys) {
                                        warn!(error = %e, "pty write failed");
                                    }
                                }
                                if let Some((rows, cols)) = last_resize {
                                    if let Err(e) = s.pty.resize(rows, cols) {
                                        // A failed TIOCSWINSZ silently diverges the kernel winsize
                                        // from the vt100 grid (full-screen-app corruption with no
                                        // breadcrumb today); warn, but still resize the emulator so
                                        // the screen geometry keeps tracking the client.
                                        warn!(error = %e, rows, cols, "pty resize failed");
                                    }
                                    s.emu.resize(rows, cols);
                                }
                                s.emu.register_input_frame(frame, now);
                                // Applied input may have resized the emulator (a direct grid change
                                // not signaled via `changed`), so re-snapshot next pass.
                                dirty = true;
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
        if !child_alive && !transport.shutdown_in_progress() {
            transport.start_shutdown(now);
        }
        for datagram in transport.tick(now) {
            channel.send(&datagram);
        }
        if transport.shutdown_in_progress()
            && (transport.shutdown_acknowledged() || transport.shutdown_ack_timed_out(now))
        {
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
    let handle = session::spawn_session(shell.as_deref(), scrollback)?;
    let _ = run_attached(conn, handle.clone()).await?;
    let _ = handle.session.lock().await.pty.kill();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{coalesce_drained_input, CursorKeyNormalizer};
    use crate::input::WireEvent;

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
}
