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
use iroh::EndpointId;
use tokio::signal::unix::{signal, SignalKind};
use tokio_util::sync::CancellationToken;

use crate::server::audit::{auth_event, Outcome};
use crate::server::session::{AttachKind, Registry, SessionSpec};
use crate::server::{run_attached, SessionExit};
use crate::transport_iroh::{
    bind_endpoint, bind_endpoint_local, bind_endpoint_with_relay, format_endpoint_id,
    parse_endpoint_id, parse_relay_url, ALPN,
};
use tracing::{error, info, warn};

/// Deadline on the QUIC crypto handshake (`Incoming::await`) before a stalled dial is dropped and
/// its connection + pending-handshake permits released (KR-01). A legitimate 1-RTT QUIC handshake
/// finishes in well under this even on a slow mobile link; the cap exists so a peer can't pin a
/// pending slot for the 300s idle timeout koh configures (`koh_transport_config`).
const ACCEPT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Configuration for [`serve`] — the clap-free, library-facing form of `koh serve`'s arguments.
///
/// The `koh` binary builds it from its `ServeArgs` via `From`; tests build it directly. [`Default`] gives the
/// same values as the CLI's defaults, with an empty `allow` list — which [`serve`] rejects, exactly
/// as the CLI does, because an allowlist entry is the sole way in.
#[derive(Debug, Clone)]
pub struct ServeConfig {
    /// Path to the persistent secret-key file (gives a stable endpoint id across restarts).
    /// `None` = the platform default server key path.
    pub key_file: Option<PathBuf>,
    /// Authorized client endpoint ids. At least one is required — koh only serves peers whose
    /// node-id is on this list.
    pub allow: Vec<String>,
    /// The program to host in the session PTY, as argv: `command[0]` is the program, the rest are
    /// its arguments, passed verbatim (no shell splitting). Empty = the user's login shell.
    pub command: Vec<String>,
    /// Scrollback lines retained by the server-side emulator (per session). 0 = no scrollback.
    /// Bounded to `0..=1_000_000`, like the CLI.
    pub scrollback: u64,
    /// Keep a detached session's shell alive this long (seconds) for the client to reconnect.
    pub session_ttl_secs: u64,
    /// Host via a self-hosted relay URL instead of n0's public relays. Takes precedence over
    /// `local` if both are set.
    pub relay_url: Option<String>,
    /// Bind without any relay/discovery (LAN / loopback). Clients dial with `--direct <ip:port>`.
    pub local: bool,
    /// Maximum number of connections being handled concurrently (minimum 1).
    pub max_connections: u32,
    /// Maximum number of distinct live sessions, one per authorized peer (minimum 1).
    pub max_sessions: u32,
}

/// The CLI's default for `--scrollback`.
pub const DEFAULT_SCROLLBACK: u64 = 1000;
/// The CLI's default for `--session-ttl-secs` (24h: mosh-style "close the laptop, reopen later").
pub const DEFAULT_SESSION_TTL_SECS: u64 = 86_400;
/// The CLI's default for `--max-connections`.
pub const DEFAULT_MAX_CONNECTIONS: u32 = 64;
/// The CLI's default for `--max-sessions`.
pub const DEFAULT_MAX_SESSIONS: u32 = 64;
/// Upper bound on `scrollback` (the CLI's `value_parser` range; re-checked in [`serve`]).
///
/// fux-vt caps each buffer at 64 Mi cells (history plus live rows, times the width), so the
/// history must leave room for a `MAX_DIM × MAX_DIM` screen or a wide resize would be refused:
/// `(65_000 + 1000) × 1000 < 64 Mi`. Pinned by a `terminal::server` test.
pub const MAX_SCROLLBACK: u64 = 65_000;

impl Default for ServeConfig {
    fn default() -> Self {
        Self {
            key_file: None,
            allow: Vec::new(),
            command: Vec::new(),
            scrollback: DEFAULT_SCROLLBACK,
            session_ttl_secs: DEFAULT_SESSION_TTL_SECS,
            relay_url: None,
            local: false,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            max_sessions: DEFAULT_MAX_SESSIONS,
        }
    }
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
///
/// The program hosted is [`ServeConfig::command`] (any argv, not only a shell). Accepts a
/// [`ServeConfig`] or anything convertible into one (the `koh` binary's `ServeArgs`).
///
/// Installs a global `tracing` subscriber writing to stderr if none is installed yet.
pub async fn serve(config: impl Into<ServeConfig>) -> anyhow::Result<()> {
    let args: ServeConfig = config.into();
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                // The crate is `koh`; there is no `koh_server` target (single-crate layout), so a
                // `koh_server=` directive matches nothing. `koh=info` covers every module; use
                // e.g. `koh::server=info` via RUST_LOG for real per-module control.
                .unwrap_or_else(|_| "koh=info".into()),
        )
        .with_writer(std::io::stderr)
        .try_init();
    let hosting = Hosting::from_config(&args)?;

    let key_file = match args.key_file.clone() {
        Some(p) => p,
        None => crate::transport_iroh::default_key_path("server")?,
    };
    let identity = crate::identity::load(&key_file)?;
    let secret = identity.secret.clone();

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
    eprintln!("│ key file    : {}", key_file.display());
    eprintln!("│ alpn        : {}", String::from_utf8_lossy(ALPN));
    eprintln!(
        "│ auth        : allowlist ({} client(s))",
        hosting.allow.len()
    );
    eprintln!("│ connect     : {connect_hint}");
    eprintln!("└───────────────────────────────────────────────────────────");

    // Always print a scannable QR of the endpoint id — point a phone camera at it instead of
    // copying 64 hex chars.
    if let Some(qr) = connect_qr(&id_str) {
        eprintln!(
            "\nScan for the endpoint id (point a phone camera at it). Assumes a dark-background \
             terminal;\non a light background it renders inverted — copy the id above instead:\n"
        );
        eprintln!("{qr}");
    } else {
        warn!("could not render the connect QR (endpoint id too large to encode)");
    }

    // Transport crypto posture (koh is a policy-taker: QUIC + TLS 1.3 come from iroh). Logged so an
    // operator can see at a glance what protects the link — and that post-quantum KEX is not yet on.
    info!(
        transport = "QUIC + TLS 1.3 (iroh)",
        kex = "X25519",
        post_quantum = false,
        "transport crypto posture"
    );

    // Graceful shutdown: a SIGTERM/SIGINT drains the accept loop cleanly (close the endpoint after
    // the reaper stops) instead of hard-killing the process.
    let shutdown = CancellationToken::new();
    spawn_signal_drain(shutdown.clone())?;
    serve_endpoint(endpoint, hosting, shutdown).await
}

/// What `koh serve` hosts, validated from a [`ServeConfig`]: who may connect, the program each
/// session runs, and the limits.
pub struct Hosting {
    allow: HashSet<EndpointId>,
    command: Arc<[String]>,
    scrollback: usize,
    session_ttl: Duration,
    max_connections: usize,
    max_sessions: usize,
}

impl Hosting {
    /// Validate the hosting part of `args`. The CLI enforces these ranges in clap; a directly built
    /// `ServeConfig` bypasses that, so they are re-checked here.
    pub fn from_config(args: &ServeConfig) -> anyhow::Result<Self> {
        anyhow::ensure!(
            args.scrollback <= MAX_SCROLLBACK,
            "scrollback {} exceeds the maximum of {MAX_SCROLLBACK}",
            args.scrollback
        );
        anyhow::ensure!(args.max_sessions >= 1, "max_sessions must be at least 1");
        // The node-id allowlist is the sole authorization gate. Every authorized peer gets the
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
        anyhow::ensure!(
            args.max_connections >= 1,
            "max_connections must be at least 1"
        );
        // Validated above (scrollback <= MAX_SCROLLBACK), so the conversions to the usize the
        // emulator, the store and the semaphores want cannot fail on any supported target.
        Ok(Self {
            allow,
            command: args.command.clone().into(),
            scrollback: usize::try_from(args.scrollback)
                .context("scrollback does not fit in usize")?,
            session_ttl: Duration::from_secs(args.session_ttl_secs),
            max_connections: usize::try_from(args.max_connections)
                .context("max_connections does not fit in usize")?,
            max_sessions: usize::try_from(args.max_sessions)
                .context("max_sessions does not fit in usize")?,
        })
    }
}

/// Serve authorized clients on an already-bound `endpoint`.
///
/// Runs until `shutdown` is cancelled or the endpoint closes, then closes it. This is `koh serve`'s
/// accept pipeline; tests run it on endpoints bound to their own transports.
pub async fn serve_endpoint(
    endpoint: iroh::Endpoint,
    hosting: Hosting,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    let allow = Arc::new(hosting.allow);
    // The registry task owns the live sessions: it creates, reattaches, caps and reaps them, so a
    // reconnecting client lands back in the same session at the current screen.
    let registry = Registry::spawn(SessionSpec {
        command: hosting.command,
        scrollback: hosting.scrollback,
        max_sessions: hosting.max_sessions,
        ttl: hosting.session_ttl,
    });

    // Bound concurrent connection-handling tasks: each accepted connection holds a permit for its
    // whole lifetime, so a flood can't spawn unbounded tasks (L-3). Excess dials are refused cheaply
    // (before the crypto handshake) via `Incoming::refuse`.
    let conn_limit = Arc::new(tokio::sync::Semaphore::new(hosting.max_connections));
    // Separate, smaller cap on *un-admitted, in-flight* handshakes (KOH-08): a slowloris that opens
    // connections but stalls the QUIC handshake (or never accepts the admission stream) would
    // otherwise pin every connection permit for the whole handshake-timeout window. A pending permit
    // is released the moment admission completes (the `drop(pending_permit)` in the accept task), so
    // established sessions never count against this — only stalls do — and excess pending dials are
    // refused cheaply (pre-handshake) like the connection cap.
    let pending_cap = hosting.max_connections.div_ceil(4).max(4);
    let handshake_limit = Arc::new(tokio::sync::Semaphore::new(pending_cap));

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
        let sessions = registry.clone();
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
            // Authenticated + authorized: free the pending-handshake slot so it isn't held for the
            // (potentially long-lived) session that follows (KOH-08). The connection-cap permit is
            // still held. The admission ack + attach happen in `serve_connection`.
            drop(pending_permit);
            serve_connection(conn, &sessions).await;
        });
    }

    // The accept loop ended (endpoint closed or a shutdown signal): stop the registry (which tears
    // down every session) before closing the endpoint.
    info!("draining: stopping the registry and closing endpoint");
    shutdown.cancel();
    registry.shutdown().await;
    endpoint.close().await;
    Ok(())
}

/// Serve one authenticated, allowlisted connection: send the admission ack, attach the peer's
/// session, and drive it. Dropping the session client on return detaches.
async fn serve_connection(conn: iroh::endpoint::Connection, registry: &Registry) {
    let peer = conn.remote_id();
    // Authorized: send the 1-byte admission ack so the client can distinguish "admitted" from a
    // deliberate reject (without it a rejected client would re-dial forever). Bounded by a short
    // timeout so a client that never accepts the stream can't pin the slot.
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
    auth_event(Outcome::Accepted, &peer, "authorized; attaching session");

    // Attach to (or create) this client's detachable session, then serve the connection.
    let Some((client, attach_kind)) = registry.attach(peer).await else {
        // At the live-session cap (L-3): refuse a brand-new peer rather than spawn an unbounded
        // shell. A reconnecting peer would have matched its existing session, so this only ever
        // rejects a genuinely new one.
        warn!(peer = %format_endpoint_id(&peer), "refusing session: at max-sessions capacity");
        conn.close(1u32.into(), b"server at session capacity");
        return;
    };
    match attach_kind {
        AttachKind::Created => {
            info!(peer = %format_endpoint_id(&peer), "started a new session");
        }
        AttachKind::Reattached { detached_for } => {
            info!(
                peer = %format_endpoint_id(&peer),
                detached_secs = detached_for.map(|d| d.as_secs()),
                "reattaching to this peer's existing session"
            );
        }
    }
    // Dropping `client` on return (or panic) detaches; the session keeps running for reattach.
    match run_attached(conn, client).await {
        Ok(SessionExit::Detached) => {
            info!(peer = %format_endpoint_id(&peer), "client detached (session retained)");
        }
        Ok(SessionExit::ShellExited) => {
            info!(peer = %format_endpoint_id(&peer), "shell exited");
        }
        Err(e) => error!(error = %e, "session loop error"),
    }
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
    use super::*;

    #[test]
    fn serve_config_default_matches_the_cli_defaults() {
        let c = ServeConfig::default();
        assert!(c.allow.is_empty() && c.command.is_empty());
        assert_eq!(c.scrollback, 1000);
        assert_eq!(c.session_ttl_secs, 86_400);
        assert_eq!(c.max_connections, 64);
        assert_eq!(c.max_sessions, 64);
        assert!(!c.local && c.relay_url.is_none() && c.key_file.is_none());
    }

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
