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

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::transport_iroh::ratelimit::FailureLimiter;
use anyhow::Context;
use clap::Args as ClapArgs;
use iroh::EndpointId;
use tokio::signal::unix::{signal, SignalKind};
use tokio_util::sync::CancellationToken;

use crate::server::{run_attached, session, SessionExit};
use crate::transport_iroh::{
    bind_endpoint, bind_endpoint_local, bind_endpoint_with_relay, format_endpoint_id,
    load_or_create_secret_key, parse_endpoint_id, parse_relay_url, MonoClock, ALPN,
};
use secrecy::{ExposeSecret, SecretString};
use tracing::{error, info, warn};

/// Auth-failure rate limit: a peer that fails (or times out) the passphrase handshake
/// [`AUTH_MAX_FAILURES`] times within [`AUTH_FAIL_WINDOW_MS`] is refused — cheaply, before the
/// expensive Argon2id KDF runs — until its older failures age out of the window. This is the
/// throttle that makes the per-guess work factor a real defense against online guessing by a
/// leaked-but-allowlisted client key, and bounds the CPU an attacker can make the server spend.
const AUTH_FAIL_WINDOW_MS: u64 = 60_000;
const AUTH_MAX_FAILURES: usize = 5;

/// Arguments for `koh serve`.
#[derive(ClapArgs, Debug)]
pub struct ServeArgs {
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

    /// Keep a detached session's shell alive this long (seconds) for the client to reconnect.
    /// Default 24h (mosh-style "close the laptop, reopen later").
    #[arg(long, default_value_t = 86_400)]
    session_ttl_secs: u64,

    /// Exit the server after this many seconds with NO active client connection (0 = never, the
    /// default). A safety net for orphaned servers — mosh's `$MOSH_SERVER_NETWORK_TMOUT`. Note it
    /// can reap a *retained, detached* session, so leave it 0 unless you want that trade-off.
    #[arg(long, env = "KOH_SERVER_NETWORK_TMOUT", default_value_t = 0)]
    network_timeout_secs: u64,

    /// Host via a self-hosted relay URL instead of n0's public relays.
    #[arg(long, value_name = "URL")]
    relay_url: Option<String>,

    /// Bind without any relay/discovery (LAN / loopback). Clients dial with --direct <ip:port>.
    #[arg(long, conflicts_with = "relay_url")]
    local: bool,

    /// Require a shared passphrase (defense-in-depth on top of the node-id allowlist).
    /// The passphrase never crosses the wire. Prefer $KOH_PASSPHRASE over this flag: a
    /// command-line argument is visible in the process table, an env var is not.
    #[arg(long)]
    passphrase: Option<String>,
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

/// Lock the shared auth-failure limiter. The single justified panic site for it: a poisoned mutex
/// is a panic-elsewhere bug, never peer-influenced input.
#[expect(
    clippy::expect_used,
    reason = "a poisoned auth-limiter mutex is a bug, not peer input"
)]
fn lock_limiter(
    limiter: &session::AuthLimiter,
) -> std::sync::MutexGuard<'_, FailureLimiter<EndpointId>> {
    limiter.lock().expect("auth limiter mutex poisoned")
}

/// `koh serve` — host a PTY shell for authorized clients over iroh.
pub async fn serve(args: ServeArgs) -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "koh_server=info,koh=info".into()),
        )
        .with_writer(std::io::stderr)
        .init();

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
        eprintln!("│ auth        : ⚠ ALLOW-ANY (insecure)");
    } else {
        eprintln!("│ auth        : allowlist ({} client(s))", allow.len());
    }
    if args.passphrase.is_some() || std::env::var("KOH_PASSPHRASE").is_ok() {
        eprintln!("│ 2nd factor  : passphrase required");
    }
    eprintln!("│ connect     : {connect_hint}");
    eprintln!("└───────────────────────────────────────────────────────────");

    // Always print a scannable QR of the endpoint id — point a phone camera at it instead of
    // copying 64 hex chars.
    if let Some(qr) = connect_qr(&id_str) {
        eprintln!("\nScan for the endpoint id (point a phone camera at it):\n");
        eprintln!("{qr}");
    } else {
        warn!("could not render the connect QR (endpoint id too large to encode)");
    }

    let shell = args.shell.clone();
    let scrollback = args.scrollback;
    let allow = std::sync::Arc::new(allow);
    let allow_any = args.allow_any;
    // Optional passphrase (a second factor); also from $KOH_PASSPHRASE. Held as a SecretString
    // so the working copy is zeroized on drop and never lands in a Debug/log dump — this reduces
    // heap exposure (the original argv/env bytes remain OS-visible, hence the env-var preference).
    // It is exposed as a &str only at the KDF call inside the handshake.
    let passphrase: std::sync::Arc<Option<SecretString>> = std::sync::Arc::new(
        args.passphrase
            .clone()
            .or_else(|| std::env::var("KOH_PASSPHRASE").ok())
            .map(SecretString::from),
    );

    // Per-peer auth-failure limiter (keyed on the client's endpoint id) + the monotonic clock its
    // window arithmetic uses. One clock, shared with every accept task and the reaper, so all the
    // `now` values share a base.
    let clock = MonoClock::new();
    let limiter: session::AuthLimiter = std::sync::Arc::new(std::sync::Mutex::new(
        FailureLimiter::new(AUTH_FAIL_WINDOW_MS, AUTH_MAX_FAILURES),
    ));

    // Detachable session store: one shell per authorized client, surviving disconnects so a
    // reconnecting client lands back in the same session at the current screen. The reaper
    // collects sessions whose shell exited or that have been detached past the TTL (and GCs the
    // auth-failure limiter on the same sweep).
    let store = session::SessionStore::default();
    let session_ttl = std::time::Duration::from_secs(args.session_ttl_secs);
    let reaper_shutdown = tokio_util::sync::CancellationToken::new();
    let reaper = tokio::spawn(session::run_reaper(
        store.clone(),
        session_ttl,
        limiter.clone(),
        clock,
        session::REAP_INTERVAL,
        reaper_shutdown.clone(),
    ));

    // Graceful shutdown: a SIGTERM/SIGINT drains the accept loop cleanly (close the endpoint after
    // the reaper stops) instead of hard-killing the process. The optional network-idle watchdog
    // cancels the same token, so a server nobody is connected to can self-exit.
    let shutdown = CancellationToken::new();
    spawn_signal_drain(shutdown.clone())?;
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
        let allow = allow.clone();
        let shell = shell.clone();
        let passphrase = passphrase.clone();
        let store = store.clone();
        let limiter = limiter.clone();
        // Counts this connection as active for the whole task; the guard decrements on every exit
        // path so the idle watchdog sees an accurate live-connection count.
        let active_guard = ConnGuard::new(active.clone());
        tokio::spawn(async move {
            let _active_guard = active_guard;
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
            // Per-peer rate limit: refuse — cheaply, before the expensive KDF — a peer that has
            // failed the handshake too many times recently. Checked after the allowlist so a
            // bogus peer can't pollute the limiter's keyspace (unless --allow-any is set, where
            // the reaper's gc bounds it).
            if !lock_limiter(&limiter).check(&peer, clock.now_ms()) {
                warn!(peer = %format_endpoint_id(&peer), "rejected: too many failed auth attempts");
                conn.close(1u32.into(), b"rate limited");
                return;
            }
            // Second factor: the passphrase nonce-challenge (no-op if none configured), bounded
            // by a 10s timeout so a stalled/malicious client can't pin a session slot.
            match tokio::time::timeout(
                std::time::Duration::from_secs(10),
                crate::transport_iroh::auth::handshake_server(
                    &conn,
                    passphrase
                        .as_ref()
                        .as_ref()
                        .map(ExposeSecret::expose_secret),
                ),
            )
            .await
            {
                Ok(Ok(())) => {
                    // Success clears this peer's failure history (a legit client that mistyped
                    // once isn't penalized after it gets in).
                    lock_limiter(&limiter).record_success(&peer);
                }
                Ok(Err(e)) => {
                    warn!(peer = %format_endpoint_id(&peer), error = %e, "passphrase handshake rejected");
                    lock_limiter(&limiter).record_failure(peer, clock.now_ms());
                    conn.close(1u32.into(), b"auth failed");
                    return;
                }
                Err(_) => {
                    warn!(peer = %format_endpoint_id(&peer), "passphrase handshake timed out");
                    lock_limiter(&limiter).record_failure(peer, clock.now_ms());
                    conn.close(1u32.into(), b"auth timeout");
                    return;
                }
            }
            info!(peer = %format_endpoint_id(&peer), "client authorized; attaching session");
            // Attach to (or create) this client's detachable session, then serve the connection.
            let (handle, attach_kind) =
                match session::attach(&store, peer, shell.as_deref(), scrollback).await {
                    Ok(pair) => pair,
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
            match run_attached(conn, handle).await {
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
