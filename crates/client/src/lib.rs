//! Library surface of `rmosh-client`: the session loop, abstracted over a [`ClientTerminal`]
//! so it can run either against the real crossterm/stdin terminal (the binary) or against a
//! scripted mock (integration tests) — no real TTY required for the latter.
//!
//! Terminal *input* (typed bytes) and *resize* events arrive as channels the caller wires up;
//! terminal *output* goes through [`ClientTerminal::render`]. The binary's `main` connects the
//! real crossterm renderer + a raw-stdin reader + a `SIGWINCH` task; a test connects a
//! capturing mock + a scripted input channel.

mod render;

use std::io::Write;
use std::time::Duration;

use rmosh_input::UserInput;
use rmosh_predict::{DisplayPreference, Overlay, PredictionEngine};
use rmosh_ssp::{RecvOutcome, Transport, SHUTDOWN_SENTINEL};
use rmosh_terminal::TerminalScreen;
use rmosh_transport_iroh::{IrohChannel, MonoClock};
use tokio::sync::mpsc;

pub use render::render;

/// The escape prefix (Ctrl-^); followed by '.' it disconnects the session.
pub const ESCAPE_PREFIX: u8 = 0x1e;

/// Where the client paints frames. The real binary writes to the terminal via crossterm; a
/// test captures cells/text as data.
pub trait ClientTerminal {
    fn render(
        &mut self,
        screen: &vt100::Screen,
        overlay: &Overlay,
        status: Option<&str>,
    ) -> std::io::Result<()>;
}

/// The production terminal: paints the synced grid + prediction overlay via crossterm.
pub struct CrosstermTerminal<W: Write> {
    pub out: W,
}

impl<W: Write> ClientTerminal for CrosstermTerminal<W> {
    fn render(
        &mut self,
        screen: &vt100::Screen,
        overlay: &Overlay,
        status: Option<&str>,
    ) -> std::io::Result<()> {
        render::render(&mut self.out, screen, overlay, status)
    }
}

/// Run a client session against `channel`, drawing through `term`.
///
/// `input_rx` carries raw typed bytes (the caller must keep its sender alive for the session;
/// when it closes, the session ends). `resize_rx` carries new `(rows, cols)` window sizes;
/// keep its sender alive even if you never resize, so the loop doesn't spin on a closed channel.
/// `initial_rows`/`initial_cols` seed the first resize sent to the server.
pub async fn run_client<T: ClientTerminal>(
    channel: IrohChannel,
    pref: DisplayPreference,
    initial_rows: u16,
    initial_cols: u16,
    mut input_rx: mpsc::Receiver<Vec<u8>>,
    mut resize_rx: mpsc::Receiver<(u16, u16)>,
    mut term: T,
) -> anyhow::Result<()> {
    let clock = MonoClock::new();
    let mut transport =
        Transport::<UserInput, TerminalScreen>::new(clock.now_ms(), channel.max_datagram_size());
    transport.set_connected(true);
    let mut predictor = PredictionEngine::new(pref);

    transport.current_mut().push_resize(initial_rows, initial_cols);

    let mut pending_escape = false;
    let mut last_recv = clock.now_ms();
    let mut dirty = true;

    loop {
        let now = clock.now_ms();
        transport.set_mtu(channel.max_datagram_size());
        if let Some(rtt) = channel.rtt_ms() {
            transport.observe_rtt(rtt);
        }
        let wait = transport.wait_time(now);
        let sleep_ms = wait.min(50);

        tokio::select! {
            biased;

            maybe = input_rx.recv() => {
                match maybe {
                    Some(chunk) => {
                        let mut quit = false;
                        let mut fwd: Vec<u8> = Vec::with_capacity(chunk.len());
                        for &b in &chunk {
                            if pending_escape {
                                pending_escape = false;
                                if b == b'.' { quit = true; break; }
                                fwd.push(ESCAPE_PREFIX);
                                fwd.push(b);
                            } else if b == ESCAPE_PREFIX {
                                pending_escape = true;
                            } else {
                                fwd.push(b);
                            }
                        }
                        if quit { break; }
                        if !fwd.is_empty() {
                            predictor.set_local_frame_sent(transport.newest_sent_num());
                            predictor.set_srtt(transport.srtt_ms());
                            let screen = transport.remote_state().screen().clone();
                            for &b in &fwd {
                                predictor.new_user_byte(now, b, &screen);
                            }
                            transport.current_mut().push_bytes(&fwd);
                            dirty = true;
                        }
                    }
                    None => break, // input source closed
                }
            }

            dg = channel.recv() => {
                match dg {
                    Ok(bytes) => {
                        if transport.recv(now, &bytes) == RecvOutcome::NewState {
                            last_recv = now;
                            let echo_ack = transport.remote_state().echo_ack();
                            let screen = transport.remote_state().screen().clone();
                            predictor.set_local_frame_late_acked(echo_ack);
                            predictor.set_srtt(transport.srtt_ms());
                            predictor.cull(now, &screen);
                            dirty = true;
                        }
                    }
                    Err(e) => {
                        tracing::info!(reason = %e, "server closed connection");
                        break;
                    }
                }
            }

            maybe = resize_rx.recv() => {
                if let Some((rows, cols)) = maybe {
                    transport.current_mut().push_resize(rows, cols);
                    predictor.reset();
                    dirty = true;
                }
                // A closed resize channel is fine; keep its sender alive to avoid spinning.
            }

            _ = tokio::time::sleep(Duration::from_millis(sleep_ms)) => {}
        }

        let now = clock.now_ms();
        for datagram in transport.tick(now) {
            channel.send(&datagram);
        }

        let staleness = now.saturating_sub(last_recv);
        let status =
            (staleness > 3000).then(|| format!("[rmosh] link down — resuming… {}s", staleness / 1000));

        if dirty || status.is_some() {
            let screen = transport.remote_state().screen();
            let overlay = predictor.overlay(screen);
            term.render(screen, &overlay, status.as_deref())?;
            dirty = false;
        }

        if transport.remote_num() == SHUTDOWN_SENTINEL {
            let screen = transport.remote_state().screen();
            let overlay = Overlay::empty();
            let _ = term.render(screen, &overlay, Some("[rmosh] session ended"));
            tokio::time::sleep(Duration::from_millis(400)).await;
            break;
        }
    }

    channel.close(0, b"client exit");
    Ok(())
}
