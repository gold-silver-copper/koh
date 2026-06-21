//! Library surface of `rmosh-server`: the per-connection session loop, reused by the binary
//! and by integration tests (so the full PTY⇄emulator⇄transport path can be exercised over a
//! real iroh connection without the `main` CLI/accept scaffolding).
//!
//! Sessions are **detachable**: the long-lived PTY+emulator lives in [`session::Session`] and
//! survives client disconnects; a per-connection [`run_attached`] loop drives a *fresh*
//! `Transport` against it, so a reconnecting client re-syncs to the current screen.

pub mod session;

use std::time::Duration;

use rmosh_input::{UserInput, WireEvent};
use rmosh_ssp::{RecvOutcome, Transport};
use rmosh_terminal::TerminalScreen;
use rmosh_transport_iroh::{IrohChannel, MonoClock};
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

    loop {
        let now = clock.now_ms();
        transport.set_mtu(channel.max_datagram_size());
        if let Some(rtt) = channel.rtt_ms() {
            transport.observe_rtt(rtt);
        }

        // Snapshot the live screen + echo-ack timing under the session lock.
        let (echo_wait, child_alive) = {
            let mut s = handle.session.lock().await;
            s.emu.set_echo_ack(now);
            *transport.current_mut() = s.emu.snapshot();
            (s.emu.echo_ack_wait_time(now), s.child_alive)
        };
        let wait = transport.wait_time(now);
        let sleep_ms = wait.min(echo_wait).min(1000);

        tokio::select! {
            // NOT biased: `changed` can hold a stored permit, which under `biased` would starve
            // client input. A fair select interleaves rendering and input.
            _ = handle.changed.notified() => { /* screen changed; the loop re-snapshots above */ }

            dg = channel.recv() => {
                match dg {
                    Ok(bytes) => {
                        let now = clock.now_ms();
                        if transport.recv(now, &bytes) == RecvOutcome::NewState {
                            let input_diff = transport.get_remote_diff();
                            if !input_diff.is_empty() {
                                let frame = transport.remote_num();
                                let mut s = handle.session.lock().await;
                                for w in &input_diff {
                                    match w {
                                        WireEvent::Keys(b) => {
                                            if let Err(e) = s.pty.write_input(b) {
                                                warn!(error = %e, "pty write failed");
                                            }
                                        }
                                        WireEvent::Resize { rows, cols } => {
                                            let _ = s.pty.resize(*rows, *cols);
                                            s.emu.resize(*rows, *cols);
                                        }
                                    }
                                }
                                s.emu.register_input_frame(frame, now);
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

/// Convenience: run a **standalone** (non-detachable) session for one connection — spawn a
/// shell, serve it, and kill it when the connection ends. Used by integration tests and any
/// caller that doesn't need reattach. The binary uses the [`session`] store + [`run_attached`].
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
