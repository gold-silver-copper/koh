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

use anyhow::Context;
use clap::Args as ClapArgs;
use iroh::EndpointId;
use koh_transport_iroh::ratelimit::FailureLimiter;

use crate::{run_attached, session, SessionExit};
use koh_transport_iroh::{
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

    /// Also print a scannable QR code of the endpoint id (point a phone camera at it instead of
    /// copying 64 hex chars). Optimized for a dark-background terminal.
    #[arg(long)]
    qr: bool,
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
    directories::ProjectDirs::from("", "", "koh").map_or_else(
        || PathBuf::from("koh-server.key"),
        |d| d.config_dir().join("server.key"),
    )
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
    let secret = load_or_create_secret_key(&key_file)
        .with_context(|| format!("loading key from {}", key_file.display()))?;

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

    if args.qr {
        if let Some(qr) = connect_qr(&id_str) {
            eprintln!("\nScan for the endpoint id (point a phone camera at it):\n");
            eprintln!("{qr}");
        } else {
            warn!("could not render the connect QR (endpoint id too large to encode)");
        }
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

    while let Some(incoming) = endpoint.accept().await {
        let allow = allow.clone();
        let shell = shell.clone();
        let passphrase = passphrase.clone();
        let store = store.clone();
        let limiter = limiter.clone();
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
                koh_transport_iroh::auth::handshake_server(
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
            let handle = match session::attach(&store, peer, shell.as_deref(), scrollback).await {
                Ok(h) => h,
                Err(e) => {
                    error!(error = %e, "failed to start session");
                    conn.close(1u32.into(), b"session error");
                    return;
                }
            };
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

    // The accept loop ended (endpoint closed): stop the reaper cleanly and wait for it to finish
    // its current sweep before tearing down the endpoint.
    reaper_shutdown.cancel();
    let _ = reaper.await;
    endpoint.close().await;
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
