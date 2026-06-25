//! The `koh serve` command.
//!
//! Binds an iroh endpoint with a persistent identity, authorizes incoming clients against a
//! node-id allowlist, and for each accepted connection runs a PTY-backed shell whose screen is
//! kept in sync with the client via the SSP over QUIC datagrams (`Transport<TerminalScreen,
//! UserInput>`).
//!
//! Auth model (deliberately *not* iroh-ssh's "anyone with the endpoint id gets a shell"):
//! a connection is only served if the client's endpoint id is on the `--allow` list (or
//! `--allow-any` is explicitly set for testing).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use clap::Args as ClapArgs;
use iroh::EndpointId;
use tokio::signal::unix::{signal, SignalKind};
use tokio_util::sync::CancellationToken;

use crate::server::audit::{auth_event, Outcome};
use crate::server::policy::{load_allow_file, Policy};
use crate::server::{run_attached, session, SessionExit};
use crate::transport_iroh::{
    bind_endpoint, bind_endpoint_local, bind_endpoint_with_relay, format_endpoint_id,
    load_or_create_secret_key, parse_endpoint_id, parse_relay_url, ALPN,
};
use tracing::{error, info, warn};

/// Deadline on the QUIC crypto handshake (`Incoming::await`) before a stalled dial is dropped and
/// its connection + pending-handshake permits released (KR-01). A legitimate 1-RTT QUIC handshake
/// finishes in well under this even on a slow mobile link; the cap exists so a peer can't pin a
/// pending slot for the 300s idle timeout koh configures (`koh_transport_config`).
const ACCEPT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Effective ceiling on a detached session's TTL when `--allow-any` is set: an unauthenticated peer
/// can spawn a shell, so a multi-hour TTL would leave abandoned shells alive far too long. The
/// authenticated-allowlist path keeps the full configured TTL (the close-laptop/reopen workflow).
const ALLOW_ANY_MAX_TTL_SECS: u64 = 600;

/// Arguments for `koh serve`.
#[derive(ClapArgs, Debug)]
pub struct ServeArgs {
    /// Path to the persistent secret-key file (gives a stable endpoint id across restarts).
    #[arg(long)]
    key_file: Option<PathBuf>,

    /// Authorize a client endpoint id (repeatable). Required unless --allow-any.
    #[arg(long = "allow", value_name = "ENDPOINT_ID")]
    allow: Vec<String>,

    /// INSECURE: accept any client — a shell to anyone who can reach the endpoint, with no
    /// allowlist. For local/testing use (pair with `--local`); on a public bind prefer
    /// `--read-only` for an observe-only screen-share. Prints a loud warning when set.
    #[arg(long)]
    allow_any: bool,

    /// Per-peer authorization policy file (sshd's `authorized_keys` options / `ForceCommand`).
    /// One entry per line: `<endpoint-id> [restrict] [command="…"]`. `restrict` = read-only (the
    /// peer's input never reaches the shell); `command="…"` runs a forced command via the login
    /// shell instead of an interactive session. `#` comments and blank lines are ignored. Peers
    /// listed here are authorized in addition to any `--allow` ids.
    #[arg(long, value_name = "PATH")]
    allow_file: Option<PathBuf>,

    /// Make every authorized client read-only: a viewer can watch the shell live, but its
    /// keystrokes and resizes never reach the PTY. Use `--allow-file` with `restrict` to make only
    /// some peers read-only.
    #[arg(long)]
    read_only: bool,

    /// Shell to run (defaults to the user's login shell).
    #[arg(long)]
    shell: Option<String>,

    /// Scrollback lines retained by the server-side emulator.
    #[arg(long, default_value_t = 1000)]
    scrollback: usize,

    /// Keep a detached session's shell alive this long (seconds) for the client to reconnect.
    /// Default 24h (mosh-style "close the laptop, reopen later").
    #[arg(long, default_value_t = 86_400)]
    session_ttl_secs: u64,

    /// Exit the server after this many seconds with NO active client connection (0 = never, the
    /// default — matches mosh). A safety net for an orphaned standalone daemon. WARNING: a non-zero
    /// value also reaps a *retained, detached* session once it has been idle this long, so a
    /// long-lived daemon should set it comfortably LONGER than --session-ttl-secs (or leave it 0).
    #[arg(long, env = "KOH_SERVER_NETWORK_TMOUT", default_value_t = 0)]
    network_timeout_secs: u64,

    /// Host via a self-hosted relay URL instead of n0's public relays.
    #[arg(long, value_name = "URL")]
    relay_url: Option<String>,

    /// Bind without any relay/discovery (LAN / loopback). Clients dial with --direct <ip:port>.
    #[arg(long, conflicts_with = "relay_url")]
    local: bool,

    /// Maximum number of connections being handled concurrently (each holds a permit for its whole
    /// lifetime; excess incoming connections are refused cheaply, before the crypto handshake). This
    /// bounds the work a flood of dials — especially under `--allow-any` — can pin on the server.
    #[arg(long, default_value_t = 64, value_parser = clap::value_parser!(u32).range(1..))]
    max_connections: u32,

    /// Maximum number of distinct live sessions (one per authorized peer). A new peer is refused
    /// once this many sessions exist; reconnecting to an existing session is always allowed. Bounds
    /// the number of real shells a flood of distinct keys can spawn under `--allow-any`.
    #[arg(long, default_value_t = 64, value_parser = clap::value_parser!(u32).range(1..))]
    max_sessions: u32,
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

fn default_key_file() -> PathBuf {
    crate::transport_iroh::default_key_path("server")
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

    // Build the allowlist as a per-peer policy map. A bare `--allow <id>` is a full read-write
    // shell (modulo the global --read-only); `--allow-file` entries carry their own restrict /
    // forced-command policy.
    let mut allow: HashMap<EndpointId, Policy> = HashMap::new();
    for s in &args.allow {
        let id = parse_endpoint_id(s).with_context(|| format!("bad --allow id: {s}"))?;
        allow.insert(
            id,
            Policy {
                read_only: args.read_only,
                force_command: None,
            },
        );
    }
    if let Some(path) = &args.allow_file {
        for (id, mut policy) in load_allow_file(path)? {
            // The global --read-only is a floor: it can only ADD the restriction, never relax a
            // per-peer one.
            policy.read_only |= args.read_only;
            if allow.insert(id, policy).is_some() {
                anyhow::bail!(
                    "endpoint id authorized by both --allow and --allow-file: {}",
                    format_endpoint_id(&id)
                );
            }
        }
    }
    if allow.is_empty() && !args.allow_any {
        anyhow::bail!(
            "no clients authorized: pass --allow <endpoint-id> (repeatable), --allow-file <path>, or --allow-any for testing"
        );
    }

    let key_file = args.key_file.clone().unwrap_or_else(default_key_file);
    let secret = load_or_create_secret_key(&key_file).with_context(|| {
        format!(
            "loading server key from {} (pass --key-file to use a writable path)",
            key_file.display()
        )
    })?;

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
    if args.allow_any {
        eprintln!("│ auth        : ⚠ ALLOW-ANY (INSECURE) — a shell to ANYONE who can reach this");
        eprintln!("│             :   endpoint, with no allowlist. Use only on trusted/local nets.");
    } else {
        eprintln!("│ auth        : allowlist ({} client(s))", allow.len());
    }
    if args.read_only {
        eprintln!("│ mode        : READ-ONLY (clients can watch, not type)");
    }
    let restricted = allow.values().filter(|p| p.read_only).count();
    let forced = allow.values().filter(|p| p.force_command.is_some()).count();
    if (restricted > 0 || forced > 0) && !args.read_only {
        eprintln!(
            "│ policy      : {restricted} restrict, {forced} forced-command (per allow-file)"
        );
    }
    if args.network_timeout_secs > 0 {
        eprintln!(
            "│ idle-timeout: {}s (server exits — reaping any detached session — after this idle)",
            args.network_timeout_secs
        );
    }
    eprintln!("│ connect     : {connect_hint}");
    eprintln!("└───────────────────────────────────────────────────────────");

    // Also surface --allow-any as a structured WARN (so it lands in logs / SIEM, not just the
    // banner). It is permitted with no extra ceremony — this is the loud notice, not a gate.
    if args.allow_any {
        warn!(
            local = args.local,
            "--allow-any is set: ANY peer that can reach this endpoint gets a shell (no allowlist). \
             Use only on trusted/local networks; prefer --read-only on a public bind."
        );
    }

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

    let shell = args.shell.clone();
    let scrollback = args.scrollback;
    let global_read_only = args.read_only;
    let allow = std::sync::Arc::new(allow);
    let allow_any = args.allow_any;

    // Detachable session store: one shell per authorized client, surviving disconnects so a
    // reconnecting client lands back in the same session at the current screen. The reaper
    // collects sessions whose shell exited or that have been detached past the TTL.
    let store = session::SessionStore::default();
    // Under --allow-any an unauthenticated peer can spawn a shell, so clamp the detached-session TTL;
    // the allowlist path keeps the full configured TTL (the close-laptop/reopen workflow).
    let effective_ttl_secs = if args.allow_any {
        args.session_ttl_secs.min(ALLOW_ANY_MAX_TTL_SECS)
    } else {
        args.session_ttl_secs
    };
    if effective_ttl_secs < args.session_ttl_secs {
        warn!(
            requested = args.session_ttl_secs,
            effective = effective_ttl_secs,
            "clamped detached-session TTL because --allow-any is set"
        );
    }
    let session_ttl = Duration::from_secs(effective_ttl_secs);
    let reaper_shutdown = tokio_util::sync::CancellationToken::new();
    let reaper = tokio::spawn(session::run_reaper(
        store.clone(),
        session_ttl,
        session::REAP_INTERVAL,
        reaper_shutdown.clone(),
    ));

    // Graceful shutdown: a SIGTERM/SIGINT drains the accept loop cleanly (close the endpoint after
    // the reaper stops) instead of hard-killing the process. The optional network-idle watchdog
    // cancels the same token, so a server nobody is connected to can self-exit.
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
    let active = Arc::new(AtomicUsize::new(0));
    if args.network_timeout_secs > 0 {
        spawn_idle_watchdog(
            active.clone(),
            Duration::from_secs(args.network_timeout_secs),
            shutdown.clone(),
        );
    }

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
        // Counts this connection as active for the whole task; the guard decrements on every exit
        // path so the idle watchdog sees an accurate live-connection count.
        let active_guard = ConnGuard::new(active.clone());
        tokio::spawn(async move {
            // Held for the whole task: releases the connection-cap permit on every exit path.
            let _permit = permit;
            let _active_guard = active_guard;
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
            if !allow_any && !allow.contains_key(&peer) {
                auth_event(Outcome::Rejected, Some(&peer), "not on allowlist");
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
            auth_event(
                Outcome::Accepted,
                Some(&peer),
                "authorized; attaching session",
            );
            // Resolve this peer's authorization policy: an explicit allow-file entry, or the default
            // (full read-write shell, plus the global --read-only if set). `restrict` = observe-only;
            // `command="…"` = a forced command instead of a login shell. Only applied on a freshly
            // created session — a reattach keeps the policy baked in at creation.
            let policy = allow.get(&peer).cloned().unwrap_or(Policy {
                read_only: global_read_only,
                force_command: None,
            });
            if policy.read_only || policy.force_command.is_some() {
                info!(
                    peer = %format_endpoint_id(&peer),
                    read_only = policy.read_only,
                    forced_command = policy.force_command.is_some(),
                    "applying per-peer policy"
                );
            }
            // Attach to (or create) this client's detachable session, then serve the connection.
            let (handle, attach_kind) = match session::attach(
                &store,
                peer,
                shell.as_deref(),
                scrollback,
                max_sessions,
                policy.force_command.as_deref(),
                policy.read_only,
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

    // The accept loop ended (endpoint closed, a shutdown signal, or the idle timeout): stop the
    // reaper + idle watchdog cleanly and wait for the reaper to finish its current sweep before
    // tearing down the endpoint. Cancelling `shutdown` here also stops the watchdog when we exited
    // because the endpoint closed on its own (rather than via the token).
    info!("draining: stopping reaper and closing endpoint");
    shutdown.cancel();
    reaper_shutdown.cancel();
    let _ = reaper.await;
    endpoint.close().await;
    Ok(())
}

/// Tracks one live client connection: increments the active count on construction and decrements it
/// on drop, so the idle watchdog sees an accurate count across every task exit path.
struct ConnGuard(Arc<AtomicUsize>);

impl ConnGuard {
    fn new(active: Arc<AtomicUsize>) -> Self {
        active.fetch_add(1, Ordering::SeqCst);
        Self(active)
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
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

/// Cancel `shutdown` once there have been zero active connections continuously for `timeout`
/// (mosh's `$MOSH_SERVER_NETWORK_TMOUT`). Polls about once a second; resets the idle clock whenever
/// a connection is live.
///
/// Clock semantics: the idle measure is the monotonic `Instant` elapsed, which PAUSES across a host
/// suspend (like the sibling `run_reaper`), so the watchdog counts *awake-idle* time — a slept laptop
/// does not accrue idle time and self-reap a retained detached session. This is deliberate; switching
/// to wall-clock (`SystemTime`) would make this default-off safety net fire across suspend, a
/// regression for the detach-and-resume workflow. (Contrast the client freeze detector, which WANTS
/// wall time to notice a long screen-off — see `client::looks_like_resume_from_freeze`.)
fn spawn_idle_watchdog(active: Arc<AtomicUsize>, timeout: Duration, shutdown: CancellationToken) {
    tokio::spawn(async move {
        let tick = Duration::from_secs(1).min(timeout);
        let mut idle_since: Option<Instant> = None;
        loop {
            tokio::select! {
                () = shutdown.cancelled() => return,
                () = tokio::time::sleep(tick) => {}
            }
            if active.load(Ordering::SeqCst) == 0 {
                let since = *idle_since.get_or_insert_with(Instant::now);
                if since.elapsed() >= timeout {
                    info!(
                        timeout_secs = timeout.as_secs(),
                        "network idle timeout; shutting down"
                    );
                    shutdown.cancel();
                    return;
                }
            } else {
                idle_since = None;
            }
        }
    });
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
