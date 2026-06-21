//! Library surface of `rmosh-server`: the per-connection session loop, reused by the binary
//! and by integration tests (so the full PTY⇄emulator⇄transport path can be exercised over a
//! real iroh connection without the `main` CLI/accept scaffolding).

use std::time::Duration;

use anyhow::Context;
use rmosh_input::{UserInput, WireEvent};
use rmosh_ssp::{RecvOutcome, Transport};
use rmosh_terminal::{ServerTerminal, TerminalScreen, DEFAULT_COLS, DEFAULT_ROWS};
use rmosh_transport_iroh::{IrohChannel, MonoClock};
use tracing::{info, warn};

/// Drive one client session: a PTY-hosted shell kept in sync with the client via
/// `Transport<TerminalScreen, UserInput>` over QUIC datagrams. Returns when the connection
/// closes or the shell exits (after a clean shutdown handshake).
pub async fn run_session(
    conn: iroh::endpoint::Connection,
    shell: Option<String>,
    scrollback: usize,
) -> anyhow::Result<()> {
    let channel = IrohChannel::new(conn);
    let clock = MonoClock::new();
    let mut transport =
        Transport::<TerminalScreen, UserInput>::new(clock.now_ms(), channel.max_datagram_size());
    transport.set_connected(true);

    let (rows, cols) = (DEFAULT_ROWS, DEFAULT_COLS);
    let mut emu = ServerTerminal::new(rows, cols, scrollback);
    let (mut pty, mut pty_rx) =
        rmosh_pty::Pty::spawn(rows, cols, shell.as_deref(), "xterm-256color")
            .context("spawning shell")?;
    *transport.current_mut() = emu.snapshot();

    let mut child_alive = true;

    loop {
        let now = clock.now_ms();
        transport.set_mtu(channel.max_datagram_size());
        if let Some(rtt) = channel.rtt_ms() {
            transport.observe_rtt(rtt);
        }
        let wait = transport.wait_time(now);
        let echo_wait = emu.echo_ack_wait_time(now);
        let sleep_ms = wait.min(echo_wait).min(1000);

        let mut dirty = false;

        tokio::select! {
            biased;

            // The child shell produced output.
            chunk = pty_rx.recv(), if child_alive => {
                match chunk {
                    Some(bytes) => { emu.process(&bytes); dirty = true; }
                    None => { child_alive = false; } // shell exited; reader hit EOF
                }
            }

            // A datagram arrived from the client.
            dg = channel.recv() => {
                match dg {
                    Ok(bytes) => {
                        let now = clock.now_ms();
                        if transport.recv(now, &bytes) == RecvOutcome::NewState {
                            let input_diff = transport.get_remote_diff();
                            if !input_diff.is_empty() {
                                let frame = transport.remote_num();
                                for w in &input_diff {
                                    match w {
                                        WireEvent::Keys(b) => {
                                            if let Err(e) = pty.write_input(b) {
                                                warn!(error = %e, "pty write failed");
                                            }
                                        }
                                        WireEvent::Resize { rows, cols } => {
                                            let _ = pty.resize(*rows, *cols);
                                            emu.resize(*rows, *cols);
                                            dirty = true;
                                        }
                                    }
                                }
                                emu.register_input_frame(frame, now);
                            }
                        }
                    }
                    Err(e) => {
                        info!(reason = %e, "connection closed by peer");
                        break;
                    }
                }
            }

            // Scheduler / echo-ack timer.
            _ = tokio::time::sleep(Duration::from_millis(sleep_ms)) => {}
        }

        let now = clock.now_ms();
        if emu.set_echo_ack(now) {
            dirty = true;
        }
        if dirty {
            *transport.current_mut() = emu.snapshot();
        }

        if !child_alive && !transport.shutdown_in_progress() {
            transport.start_shutdown(now);
        }

        for datagram in transport.tick(now) {
            channel.send(&datagram);
        }

        if transport.shutdown_in_progress()
            && (transport.shutdown_acknowledged() || transport.shutdown_ack_timed_out(now))
        {
            break;
        }
    }

    channel.close(0, b"session ended");
    let _ = pty.kill();
    Ok(())
}
