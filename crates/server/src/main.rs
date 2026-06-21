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

use anyhow::Context;
use clap::Parser;
use iroh::EndpointId;
use rmosh_server::run_session;
use rmosh_transport_iroh::{
    bind_endpoint, bind_endpoint_local, bind_endpoint_with_relay, format_endpoint_id,
    load_or_create_secret_key, parse_endpoint_id, parse_relay_url, ALPN,
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

    /// Host via a self-hosted relay URL instead of n0's public relays.
    #[arg(long, value_name = "URL")]
    relay_url: Option<String>,

    /// Bind without any relay/discovery (LAN / loopback). Clients dial with --direct <ip:port>.
    #[arg(long, conflicts_with = "relay_url")]
    local: bool,

    /// Require a shared passphrase (defense-in-depth on top of the node-id allowlist).
    /// The passphrase never crosses the wire. Also read from $RMOSH_PASSPHRASE.
    #[arg(long)]
    passphrase: Option<String>,
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

    // Pick the network profile: self-hosted relay, relay-less LAN/loopback, or default n0.
    let endpoint = if let Some(url) = &args.relay_url {
        let relay = parse_relay_url(url)?;
        bind_endpoint_with_relay(secret, true, relay).await.context("binding endpoint")?
    } else if args.local {
        bind_endpoint_local(secret, true).await.context("binding endpoint")?
    } else {
        bind_endpoint(secret, true).await.context("binding endpoint")?
    };
    let my_id = endpoint.id();
    let id_str = format_endpoint_id(&my_id);

    // How a client should dial us, given the chosen profile.
    let connect_hint = if let Some(url) = &args.relay_url {
        format!("rmosh-client {id_str} --relay-url {url}")
    } else if args.local {
        let port = endpoint
            .bound_sockets()
            .iter()
            .find(|s| s.is_ipv4())
            .map(|s| s.port())
            .unwrap_or(0);
        format!("rmosh-client {id_str} --direct <this-host-ip>:{port}")
    } else {
        format!("rmosh-client {id_str}")
    };

    eprintln!("┌─ rmosh-server ready ──────────────────────────────────────");
    eprintln!("│ endpoint id : {id_str}");
    eprintln!("│ key file    : {}", key_file.display());
    eprintln!("│ alpn        : {}", String::from_utf8_lossy(ALPN));
    if args.allow_any {
        eprintln!("│ auth        : ⚠ ALLOW-ANY (insecure)");
    } else {
        eprintln!("│ auth        : allowlist ({} client(s))", allow.len());
    }
    if args.passphrase.is_some() || std::env::var("RMOSH_PASSPHRASE").is_ok() {
        eprintln!("│ 2nd factor  : passphrase required");
    }
    eprintln!("│ connect     : {connect_hint}");
    eprintln!("└───────────────────────────────────────────────────────────");

    let shell = args.shell.clone();
    let scrollback = args.scrollback;
    let allow = std::sync::Arc::new(allow);
    let allow_any = args.allow_any;
    // Optional passphrase (a second factor); also from $RMOSH_PASSPHRASE.
    let passphrase = std::sync::Arc::new(
        args.passphrase
            .clone()
            .or_else(|| std::env::var("RMOSH_PASSPHRASE").ok()),
    );

    while let Some(incoming) = endpoint.accept().await {
        let allow = allow.clone();
        let shell = shell.clone();
        let passphrase = passphrase.clone();
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
            // Second factor: the passphrase nonce-challenge (no-op if none configured), bounded
            // by a 10s timeout so a stalled/malicious client can't pin a session slot.
            match tokio::time::timeout(
                std::time::Duration::from_secs(10),
                rmosh_transport_iroh::auth::handshake_server(&conn, passphrase.as_deref()),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    warn!(peer = %format_endpoint_id(&peer), error = %e, "passphrase handshake rejected");
                    conn.close(1u32.into(), b"auth failed");
                    return;
                }
                Err(_) => {
                    warn!(peer = %format_endpoint_id(&peer), "passphrase handshake timed out");
                    conn.close(1u32.into(), b"auth timeout");
                    return;
                }
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
