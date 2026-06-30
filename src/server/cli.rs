//! The `koh serve` command.
//!
//! Binds an iroh endpoint with a persistent identity, authorizes incoming clients against a
//! node-id allowlist, and for each accepted connection runs a PTY-backed shell whose screen is
//! kept in sync with the client via the SSP over QUIC datagrams (`Transport<TerminalScreen,
//! UserInput>`).
//!
//! Auth model (deliberately *not* iroh-ssh's "anyone with the endpoint id gets a shell"):
//! a connection is only served if the client's endpoint id is on the `--allow` list. There is no
//! "accept any peer" escape hatch — an allowlist entry is the sole way in.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use clap::Args as ClapArgs;
use iroh::EndpointId;
use tokio::signal::unix::{signal, SignalKind};
use tokio_util::sync::CancellationToken;

use crate::server::audit::{auth_event, Outcome};
use crate::server::{run_attached, session, SessionExit};
use crate::transport_iroh::{
    bind_endpoint, bind_endpoint_local, bind_endpoint_with_relay, format_endpoint_id,
    generate_secret_key, load_or_create_secret_key, parse_endpoint_id, parse_relay_url, ALPN,
};
use tracing::{error, info, warn};

/// Deadline on the QUIC crypto handshake (`Incoming::await`) before a stalled dial is dropped and
/// its connection + pending-handshake permits released (KR-01). A legitimate 1-RTT QUIC handshake
/// finishes in well under this even on a slow mobile link; the cap exists so a peer can't pin a
/// pending slot for the 300s idle timeout koh configures (`koh_transport_config`).
const ACCEPT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Arguments for `koh serve`.
#[derive(ClapArgs, Debug)]
pub struct ServeArgs {
    /// Path to the persistent secret-key file (gives a stable endpoint id across restarts).
    #[arg(long)]
    key_file: Option<PathBuf>,

    /// Authorize a client endpoint id (repeatable). At least one is required — koh only serves
    /// peers whose node-id is on this list.
    #[arg(long = "allow", value_name = "ENDPOINT_ID")]
    allow: Vec<String>,

    /// Shell to run (defaults to the user's login shell).
    #[arg(long)]
    shell: Option<String>,

    /// Scrollback lines retained by the server-side emulator (per session). Bounded like the other
    /// resource knobs (`--max-connections`/`--max-sessions`): vt100 allocates the grid eagerly, so an
    /// unbounded value × `--max-sessions` is a memory footgun. 0 = no scrollback.
    #[arg(long, default_value_t = 1000, value_parser = clap::value_parser!(u64).range(0..=1_000_000))]
    scrollback: u64,

    /// Keep a detached session's shell alive this long (seconds) for the client to reconnect.
    /// Default 24h (mosh-style "close the laptop, reopen later").
    #[arg(long, default_value_t = 86_400)]
    session_ttl_secs: u64,

    /// Host via a self-hosted relay URL instead of n0's public relays.
    #[arg(long, value_name = "URL")]
    relay_url: Option<String>,

    /// Bind without any relay/discovery (LAN / loopback). Clients dial with --direct <ip:port>.
    #[arg(long, conflicts_with = "relay_url")]
    local: bool,

    /// Maximum number of connections being handled concurrently (each holds a permit for its whole
    /// lifetime; excess incoming connections are refused cheaply, before the crypto handshake). This
    /// bounds the work a flood of dials can pin on the server before the allowlist check rejects them.
    #[arg(long, default_value_t = 64, value_parser = clap::value_parser!(u32).range(1..))]
    max_connections: u32,

    /// Maximum number of distinct live sessions (one per authorized peer). A new peer is refused
    /// once this many sessions exist; reconnecting to an existing session is always allowed. Bounds
    /// the number of real shells a flood of authorized keys can spawn.
    #[arg(long, default_value_t = 64, value_parser = clap::value_parser!(u32).range(1..))]
    max_sessions: u32,

    /// Use an in-memory server identity for an SSH-bootstrapped one-shot server.
    #[arg(long, hide = true)]
    ephemeral_key: bool,

    /// Print a machine-readable endpoint id marker to stdout after binding.
    #[arg(long, hide = true)]
    print_id_stdout: bool,

    /// Do not render the QR code. Useful for machine-driven bootstraps.
    #[arg(long, hide = true)]
    no_qr: bool,
}

/// Render `data` as a QR code for a **dark-background** terminal, or `None` if it is too large to
/// encode. The polarity follows the `qrcode` crate's documented terminal recipe — QR-dark modules
/// become the terminal background and QR-light modules the foreground blocks — so a phone camera
/// reads it as a normal dark-on-light code. (A light-background terminal would see it inverted.)
fn connect_qr(data: &str) -> Option<String> {
    use qrcode::render::unicode::Dense1x2;
    let code = qrcode::QrCode::new(data).ok()?;
    Some(
        code.render::<Dense1x2>()
            .dark_color(Dense1x2::Light)
            .light_color(Dense1x2::Dark)
            .quiet_zone(true)
            .build(),
    )
}

/// `koh serve` — host a PTY shell for authorized clients over iroh.
pub async fn serve(args: ServeArgs) -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                // The crate is `koh`; there is no `koh_server` target (single-crate layout), so a
                // `koh_server=` directive matches nothing. `koh=info` covers every module; use
                // e.g. `koh::server=info` via RUST_LOG for real per-module control.
                .unwrap_or_else(|_| "koh=info".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    // Build the node-id allowlist — the sole authorization gate. Every authorized peer gets the
    // same access. At least one entry is required: koh never serves an unlisted peer.
    let mut allow: HashSet<EndpointId> = HashSet::new();
    for s in &args.allow {
        let id = parse_endpoint_id(s).with_context(|| format!("bad --allow id: {s}"))?;
        allow.insert(id);
    }
    if allow.is_empty() {
        anyhow::bail!(
            "no clients authorized: pass --allow <endpoint-id> (repeatable; get one from `koh id`)"
        );
    }

    let (secret, key_file_label) = if args.ephemeral_key {
        (generate_secret_key(), "(ephemeral)".to_string())
    } else {
        let key_file = match args.key_file.clone() {
            Some(p) => p,
            None => crate::transport_iroh::default_key_path("server")?,
        };
        let secret = load_or_create_secret_key(&key_file).with_context(|| {
            format!(
                "loading server key from {} (pass --key-file to use a writable path)",
                key_file.display()
            )
        })?;
        (secret, key_file.display().to_string())
    };

    // Pick the network profile: self-hosted relay, relay-less LAN/loopback, or default n0.
    let endpoint = if let Some(url) = &args.relay_url {
        let relay = parse_relay_url(url)?;
        bind_endpoint_with_relay(secret, true, relay)
            .await
            .context("binding endpoint")?
    } else if args.local {
        bind_endpoint_local(secret, true)
            .await
            .context("binding endpoint")?
    } else {
        bind_endpoint(secret, true)
            .await
            .context("binding endpoint")?
    };
    let my_id = endpoint.id();
    let id_str = format_endpoint_id(&my_id);

    // How a client should dial us, given the chosen profile.
    let connect_hint = if let Some(url) = &args.relay_url {
        format!("koh connect {id_str} --relay-url {url}")
    } else if args.local {
        let port = endpoint
            .bound_sockets()
            .iter()
            .find(|s| s.is_ipv4())
            .map_or(0, std::net::SocketAddr::port);
        format!("koh connect {id_str} --direct <this-host-ip>:{port}")
    } else {
        format!("koh connect {id_str}")
    };

    eprintln!("┌─ koh server ready ──────────────────────────────────────");
    eprintln!("│ endpoint id : {id_str}");
    eprintln!("│ key file    : {key_file_label}");
    eprintln!("│ alpn        : {}", String::from_utf8_lossy(ALPN));
    eprintln!("│ auth        : allowlist ({} client(s))", allow.len());
    eprintln!("│ connect     : {connect_hint}");
    eprintln!("└───────────────────────────────────────────────────────────");

    if args.print_id_stdout {
        use std::io::Write as _;
        println!("KOH_BOOTSTRAP_ENDPOINT_ID={id_str}");
        std::io::stdout()
            .flush()
            .context("flushing bootstrap endpoint id")?;
    }

    // Always print a scannable QR of the endpoint id — point a phone camera at it instead of
    // copying 64 hex chars, unless a machine-driven bootstrap disabled it.
    if !args.no_qr {
        if let Some(qr) = connect_qr(&id_str) {
            eprintln!(
                "\nScan for the endpoint id (point a phone camera at it). Assumes a dark-background \
                 terminal;\non a light background it renders inverted — copy the id above instead:\n"
            );
            eprintln!("{qr}");
        } else {
            warn!("could not render the connect QR (endpoint id too large to encode)");
        }
    }

    // Transport crypto posture (koh is a policy-taker: QUIC + TLS 1.3 come from iroh). Logged so an
    // operator can see at a glance what protects the link — and that post-quantum KEX is not yet on.
    info!(
        transport = "QUIC + TLS 1.3 (iroh)",
        kex = "X25519",
        post_quantum = false,
        "transport crypto posture"
    );

    let shell = args.shell.clone();
    // Cast the validated u64 (clap range 0..=1_000_000) down to the usize the emulator wants.
    let scrollback = args.scrollback as usize;
    let allow = std::sync::Arc::new(allow);

    // Detachable session store: one shell per authorized client, surviving disconnects so a
    // reconnecting client lands back in the same session at the current screen. The reaper
    // collects sessions whose shell exited or that have been detached past the TTL.
    let store = session::SessionStore::default();
    let session_ttl = Duration::from_secs(args.session_ttl_secs);
    let reaper_shutdown = tokio_util::sync::CancellationToken::new();
    let reaper = tokio::spawn(session::run_reaper(
        store.clone(),
        session_ttl,
        session::REAP_INTERVAL,
        reaper_shutdown.clone(),
    ));

    // Graceful shutdown: a SIGTERM/SIGINT drains the accept loop cleanly (close the endpoint after
    // the reaper stops) instead of hard-killing the process.
    let shutdown = CancellationToken::new();
    spawn_signal_drain(shutdown.clone())?;
    // Bound concurrent connection-handling tasks: each accepted connection holds a permit for its
    // whole lifetime, so a flood can't spawn unbounded tasks (L-3). Excess dials are refused cheaply
    // (before the crypto handshake) via `Incoming::refuse`.
    let conn_limit = Arc::new(tokio::sync::Semaphore::new(args.max_connections as usize));
    // Separate, smaller cap on *un-admitted, in-flight* handshakes (KOH-08): a slowloris that opens
    // connections but stalls the QUIC handshake (or never accepts the admission stream) would
    // otherwise pin every connection permit for the whole handshake-timeout window. A pending permit
    // is released the moment admission completes (the `drop(pending_permit)` in the accept task), so
    // established sessions never count against this — only stalls do — and excess pending dials are
    // refused cheaply (pre-handshake) like the connection cap.
    let pending_cap = (args.max_connections as usize).div_ceil(4).max(4);
    let handshake_limit = Arc::new(tokio::sync::Semaphore::new(pending_cap));
    let max_sessions = args.max_sessions as usize;

    loop {
        let incoming = tokio::select! {
            biased;
            () = shutdown.cancelled() => break,
            inc = endpoint.accept() => match inc {
                Some(i) => i,
                None => break, // endpoint closed
            },
        };
        // Connection cap (L-3): grab a permit before doing any work for this connection. If the
        // server is at capacity, refuse the incoming dial cheaply — `refuse()` rejects it without
        // the (expensive) crypto handshake, so a flood can't pin unbounded resources.
        // --- Trust-boundary admission pipeline (AR-06) ---
        // An accepted connection runs an ORDERED gauntlet before it gets a session, deliberately
        // inlined so each control is a single local edit and the order reads as one sequence:
        //   (1) connection-cap permit, (2) pending-handshake permit (KOH-08), then in the task:
        //   (3) QUIC-handshake timeout (KR-01), (4) node-id allowlist, (5) a 1-byte admission ack so
        //   the client can tell "admitted" from a deliberate reject, then attach. Authorization is the
        //   allowlist — the peer's node-id is already cryptographically authenticated by the QUIC/TLS
        //   handshake, so there is no passphrase/second-factor step. The pure controls (allowlist /
        //   caps / admission) live in session.rs / transport_iroh::admission with their own tests; what
        //   stays here is the I/O-bound permit/guard ownership dance.
        let Ok(permit) = conn_limit.clone().try_acquire_owned() else {
            warn!("refusing connection: at max-connections capacity");
            incoming.refuse();
            continue;
        };
        // Pending-handshake cap (KOH-08): refuse if too many un-authenticated handshakes are
        // already in flight, so stalls can't consume the whole connection budget. (`permit` above
        // is released on this `continue`.)
        let Ok(pending_permit) = handshake_limit.clone().try_acquire_owned() else {
            warn!("refusing connection: too many handshakes in flight");
            incoming.refuse();
            continue;
        };
        let allow = allow.clone();
        let shell = shell.clone();
        let store = store.clone();
        tokio::spawn(async move {
            // Held for the whole task: releases the connection-cap permit on every exit path.
            let _permit = permit;
            // Held only until auth completes (dropped explicitly on success, or on any early
            // return below), so an established session doesn't occupy a pending-handshake slot.
            let pending_permit = pending_permit;
            // Bound the QUIC handshake itself (KR-01): `incoming.await` has no internal deadline
            // short of iroh's 300s idle timeout, so a peer that yields an `Incoming` then stalls
            // would otherwise pin this conn + pending permit for ~5 min — and ~`pending_cap` such
            // stalls would deny all new connections. The timeout releases both permits promptly.
            let conn = match tokio::time::timeout(ACCEPT_HANDSHAKE_TIMEOUT, incoming).await {
                Ok(Ok(c)) => c,
                Ok(Err(e)) => {
                    warn!(error = %e, "incoming handshake failed");
                    return;
                }
                Err(_) => {
                    warn!("incoming handshake timed out (stalled QUIC handshake)");
                    return;
                }
            };
            let peer = conn.remote_id();
            if !allow.contains(&peer) {
                auth_event(Outcome::Rejected, &peer, "not on allowlist");
                conn.close(1u32.into(), b"not authorized");
                return;
            }
            // Authorized: send the 1-byte admission ack so the client can distinguish "admitted"
            // from a deliberate reject (without it a rejected client would re-dial forever). Bounded
            // by a short timeout so a client that never accepts the stream can't pin the slot.
            match tokio::time::timeout(
                Duration::from_secs(3),
                crate::transport_iroh::admission::admit(&conn),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    warn!(error = %e, "admission ack failed");
                    return;
                }
                Err(_) => {
                    warn!("admission ack timed out");
                    return;
                }
            }
            // Admitted: free the pending-handshake slot so it isn't held for the (potentially
            // long-lived) session that follows (KOH-08). The connection-cap permit is still held.
            drop(pending_permit);
            auth_event(Outcome::Accepted, &peer, "authorized; attaching session");
            // Attach to (or create) this client's detachable session, then serve the connection.
            let (handle, attach_kind) = match session::attach(
                &store,
                peer,
                shell.as_deref(),
                scrollback,
                max_sessions,
            )
            .await
            {
                Ok(Some(pair)) => pair,
                Ok(None) => {
                    // At the live-session cap (L-3): refuse a brand-new peer rather than spawn
                    // an unbounded shell. A reconnecting peer would have matched an existing
                    // session above, so this only ever rejects a genuinely new one.
                    warn!(peer = %format_endpoint_id(&peer), "refusing session: at max-sessions capacity");
                    conn.close(1u32.into(), b"server at session capacity");
                    return;
                }
                Err(e) => {
                    error!(error = %e, "failed to start session");
                    conn.close(1u32.into(), b"session error");
                    return;
                }
            };
            match attach_kind {
                session::AttachKind::Created => {
                    info!(peer = %format_endpoint_id(&peer), "started a new session");
                }
                session::AttachKind::Reattached { detached_for } => {
                    // mosh-server's "you have a detached session" notice, server-side: this peer is
                    // resuming its running session rather than starting a fresh one.
                    info!(
                        peer = %format_endpoint_id(&peer),
                        detached_secs = detached_for.map(|d| d.as_secs()),
                        "reattaching to this peer's existing session"
                    );
                }
            }
            // Arm a RAII safety net BEFORE serving: if `run_attached` unwinds (panics), the guard's
            // Drop still releases this connection's session attach so it can't leak (K-16). On a
            // normal return we disarm and run the precise detach/reap below ourselves.
            let attach_guard = session::AttachGuard::new(store.clone(), peer);
            let outcome = run_attached(conn, handle).await;
            attach_guard.disarm();
            match outcome {
                Ok(SessionExit::Detached) => {
                    // Keep the shell running for reattach.
                    session::detach(&store, peer).await;
                    info!(peer = %format_endpoint_id(&peer), "client detached (session retained)");
                }
                Ok(SessionExit::ShellExited) => {
                    session::reap(&store, peer).await;
                    info!(peer = %format_endpoint_id(&peer), "shell exited; session reaped");
                }
                Err(e) => {
                    error!(error = %e, "session loop error");
                    session::detach(&store, peer).await;
                }
            }
        });
    }

    // The accept loop ended (endpoint closed or a shutdown signal): stop the reaper cleanly and wait
    // for it to finish its current sweep before tearing down the endpoint.
    info!("draining: stopping reaper and closing endpoint");
    shutdown.cancel();
    reaper_shutdown.cancel();
    let _ = reaper.await;
    endpoint.close().await;
    Ok(())
}

/// Cancel `shutdown` on the first SIGTERM/SIGINT so the accept loop drains gracefully (rather than
/// the process dying mid-session). Returns an error only if a handler can't be installed.
fn spawn_signal_drain(shutdown: CancellationToken) -> anyhow::Result<()> {
    let mut term = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
    let mut intr = signal(SignalKind::interrupt()).context("installing SIGINT handler")?;
    tokio::spawn(async move {
        tokio::select! {
            _ = term.recv() => {}
            _ = intr.recv() => {}
        }
        info!("received shutdown signal; draining");
        shutdown.cancel();
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::connect_qr;

    #[test]
    fn connect_qr_renders_an_id_and_handles_overlong_input() {
        // A 64-hex endpoint id is well within QR capacity: renders to a multi-row block grid.
        let id = "3f9c".repeat(16);
        let qr = connect_qr(&id).expect("an endpoint id must fit in a QR");
        assert!(qr.lines().count() > 5, "a QR should be a multi-row block");
        assert!(
            qr.contains('█') || qr.contains('▀') || qr.contains('▄'),
            "the unicode renderer uses half-block glyphs"
        );
        // Far beyond QR capacity (~2953 bytes): graceful None, never a panic.
        assert!(
            connect_qr(&"a".repeat(10_000)).is_none(),
            "overlong input must return None, not panic"
        );
    }
}
