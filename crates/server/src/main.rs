//! # rmosh-server
//!
//! The server end of an rmosh session: binds an iroh endpoint with a persistent identity,
//! authorizes incoming clients against a node-id allowlist, and for each accepted connection
//! runs a PTY-backed shell whose screen is kept in sync with the client via the SSP over
//! QUIC datagrams (`Transport<TerminalScreen, UserInput>`).
//!
//! Auth model (deliberately *not* iroh-ssh's "anyone with the endpoint id gets a shell"):
//! a connection is only served if the client's endpoint id is on the `--allow` list (or
//! `--allow-any` is explicitly set for testing).

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use iroh::EndpointId;
use rmosh_input::{UserInput, WireEvent};
use rmosh_ssp::{RecvOutcome, Transport};
use rmosh_terminal::{ServerTerminal, TerminalScreen, DEFAULT_COLS, DEFAULT_ROWS};
use rmosh_transport_iroh::{
    bind_endpoint, format_endpoint_id, load_or_create_secret_key, parse_endpoint_id, IrohChannel,
    MonoClock, ALPN,
};
use tracing::{error, info, warn};

#[derive(Parser, Debug)]
#[command(name = "rmosh-server", about = "mosh-over-iroh server (PTY shell host)")]
struct Args {
    /// Path to the persistent secret-key file (gives a stable endpoint id across restarts).
    #[arg(long)]
    key_file: Option<PathBuf>,

    /// Authorize a client endpoint id (repeatable). Required unless --allow-any.
    #[arg(long = "allow", value_name = "ENDPOINT_ID")]
    allow: Vec<String>,

    /// INSECURE: accept any client. For local testing only.
    #[arg(long)]
    allow_any: bool,

    /// Shell to run (defaults to the user's login shell).
    #[arg(long)]
    shell: Option<String>,

    /// Scrollback lines retained by the server-side emulator.
    #[arg(long, default_value_t = 1000)]
    scrollback: usize,
}

fn default_key_file() -> PathBuf {
    directories::ProjectDirs::from("", "", "rmosh")
        .map(|d| d.config_dir().join("server.key"))
        .unwrap_or_else(|| PathBuf::from("rmosh-server.key"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "rmosh_server=info,rmosh=info".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let args = Args::parse();

    // Build the allowlist.
    let mut allow: HashSet<EndpointId> = HashSet::new();
    for s in &args.allow {
        let id = parse_endpoint_id(s).with_context(|| format!("bad --allow id: {s}"))?;
        allow.insert(id);
    }
    if allow.is_empty() && !args.allow_any {
        anyhow::bail!(
            "no clients authorized: pass --allow <endpoint-id> (repeatable), or --allow-any for testing"
        );
    }

    let key_file = args.key_file.clone().unwrap_or_else(default_key_file);
    let secret = load_or_create_secret_key(&key_file)
        .with_context(|| format!("loading key from {}", key_file.display()))?;
    let endpoint = bind_endpoint(secret, true).await.context("binding endpoint")?;
    let my_id = endpoint.id();

    eprintln!("┌─ rmosh-server ready ──────────────────────────────────────");
    eprintln!("│ endpoint id : {}", format_endpoint_id(&my_id));
    eprintln!("│ key file    : {}", key_file.display());
    eprintln!("│ alpn        : {}", String::from_utf8_lossy(ALPN));
    if args.allow_any {
        eprintln!("│ auth        : ⚠ ALLOW-ANY (insecure)");
    } else {
        eprintln!("│ auth        : allowlist ({} client(s))", allow.len());
    }
    eprintln!("│ connect     : rmosh-client {}", format_endpoint_id(&my_id));
    eprintln!("└───────────────────────────────────────────────────────────");

    let shell = args.shell.clone();
    let scrollback = args.scrollback;
    let allow = std::sync::Arc::new(allow);
    let allow_any = args.allow_any;

    while let Some(incoming) = endpoint.accept().await {
        let allow = allow.clone();
        let shell = shell.clone();
        tokio::spawn(async move {
            let conn = match incoming.await {
                Ok(c) => c,
                Err(e) => {
                    warn!(error = %e, "incoming handshake failed");
                    return;
                }
            };
            let peer = conn.remote_id();
            if !allow_any && !allow.contains(&peer) {
                warn!(peer = %format_endpoint_id(&peer), "rejected: not on allowlist");
                conn.close(1u32.into(), b"not authorized");
                return;
            }
            info!(peer = %format_endpoint_id(&peer), "client authorized; starting session");
            if let Err(e) = run_session(conn, shell, scrollback).await {
                error!(error = %e, "session ended with error");
            }
            info!(peer = %format_endpoint_id(&peer), "session ended");
        });
    }

    endpoint.close().await;
    Ok(())
}

/// Drive one client session: PTY shell ⇄ `Transport<TerminalScreen, UserInput>` over datagrams.
async fn run_session(
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
    let (mut pty, mut pty_rx) = rmosh_pty::Pty::spawn(rows, cols, shell.as_deref(), "xterm-256color")
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
                                // Remember when this input frame arrived, for echo-ack debounce.
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

        // Begin a clean shutdown once the shell has exited.
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
