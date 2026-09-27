//! The `koh serve` command: bind an endpoint with a persistent identity, admit only the clients on
//! the `--allow` list, and host each one's session. There is no "accept any peer" mode.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use iroh::{EndpointId, RelayUrl};
use tokio::signal::unix::SignalKind;
use tokio_util::sync::CancellationToken;

use crate::server::audit::{auth_event, Outcome};
use crate::server::session::{AttachKind, Registry, SessionSpec};
use crate::server::{run_attached, SessionExit};
use crate::transport_iroh::{bind_endpoint, bind_endpoint_local, bind_endpoint_with_relay, ALPN};
use tracing::{error, info, warn};

/// Deadline on the QUIC handshake, so a stalled dial cannot hold its permits for the 5-minute idle
/// timeout; a real handshake takes far less, even on a slow mobile link.
const ACCEPT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The clap-free form of `koh serve`'s arguments. [`Default`] gives the CLI's defaults, with an
/// empty `allow`, which [`serve`] rejects.
#[derive(Debug, Clone)]
pub struct ServeConfig {
    /// The secret-key file; `None` for the default server key path.
    pub key_file: Option<PathBuf>,
    /// The client endpoint ids allowed in; at least one.
    pub allow: Vec<EndpointId>,
    /// The program each session runs, as argv, verbatim; empty for the login shell.
    pub command: Vec<String>,
    /// Scrollback lines each session's emulator keeps, at most [`MAX_SCROLLBACK`].
    pub scrollback: u64,
    /// How long a detached session lives, in seconds.
    pub session_ttl_secs: u64,
    /// A self-hosted relay instead of n0's; wins over `local`.
    pub relay_url: Option<RelayUrl>,
    /// No relay or discovery; clients dial with `--direct <ip:port>`.
    pub local: bool,
    /// Most connections handled at once (at least 1).
    pub max_connections: u32,
    /// Most live sessions, one per peer (at least 1).
    pub max_sessions: u32,
    /// The binary each session's program starts through: by default the running one, which hands
    /// `__launch` to [`crate::pty::launched`].
    pub launcher: crate::pty::Launcher,
}

/// The CLI's default for `--scrollback`.
pub const DEFAULT_SCROLLBACK: u64 = 1000;
/// The CLI's default for `--session-ttl-secs`: a day, to close the laptop and reopen it later.
pub const DEFAULT_SESSION_TTL_SECS: u64 = 86_400;
/// The CLI's default for `--max-connections`.
pub const DEFAULT_MAX_CONNECTIONS: u32 = 64;
/// The CLI's default for `--max-sessions`.
pub const DEFAULT_MAX_SESSIONS: u32 = 64;
/// Upper bound on `scrollback`. fux-vt caps a buffer at 64 Mi cells, which must hold the history
/// and a `MAX_DIM × MAX_DIM` screen: `(65_000 + 1000) × 1000 < 64 Mi`.
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
            launcher: crate::pty::Launcher::this_binary(),
        }
    }
}

/// `data` as a QR code for a dark-background terminal (dark modules drawn as the background, so a
/// camera reads dark on light), or `None` if it is too large to encode.
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

/// `koh serve`: host [`ServeConfig::command`] for the allowed clients until SIGTERM or SIGINT.
/// Logs to stderr.
pub async fn serve(args: ServeConfig) -> anyhow::Result<()> {
    crate::log::init(std::io::stderr, tracing::Level::INFO);
    let hosting = Hosting::from_config(&args)?;

    let key_file = crate::identity::key_path(args.key_file.clone(), "server")?;
    let identity = crate::identity::load(&key_file)?;
    let secret = identity.secret.clone();

    // Pick the network profile: self-hosted relay, relay-less LAN/loopback, or default n0.
    let endpoint = match (&args.relay_url, args.local) {
        (Some(relay), _) => bind_endpoint_with_relay(secret, true, relay.clone()).await,
        (None, true) => bind_endpoint_local(secret, true).await,
        (None, false) => bind_endpoint(secret, true).await,
    }
    .context("binding endpoint")?;
    let my_id = endpoint.id();
    let id_str = my_id.to_string();

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

    // A phone camera can read the id instead of anyone copying 64 hex digits.
    if let Some(qr) = connect_qr(&id_str) {
        eprintln!(
            "\nScan for the endpoint id (point a phone camera at it). Assumes a dark-background \
             terminal;\non a light background it renders inverted — copy the id above instead:\n"
        );
        eprintln!("{qr}");
    } else {
        warn!("could not render the connect QR (endpoint id too large to encode)");
    }

    // What protects the link, iroh's choice: so an operator sees post-quantum KEX is not on.
    info!(
        transport = "QUIC + TLS 1.3 (iroh)",
        kex = "X25519",
        post_quantum = false,
        "transport crypto posture"
    );

    let shutdown = CancellationToken::new();
    crate::cancel_on_signals(
        &shutdown,
        &[SignalKind::terminate(), SignalKind::interrupt()],
    )
    .context("installing the signal handlers")?;
    serve_endpoint(endpoint, hosting, shutdown).await
}

/// A validated [`ServeConfig`]: who may connect, what each session runs, and the limits.
pub struct Hosting {
    allow: HashSet<EndpointId>,
    command: Arc<[String]>,
    scrollback: usize,
    session_ttl: Duration,
    max_connections: usize,
    max_sessions: usize,
    launcher: crate::pty::Launcher,
}

impl Hosting {
    /// Validate `args`: clap checks these ranges, but a `ServeConfig` built in code does not.
    pub fn from_config(args: &ServeConfig) -> anyhow::Result<Self> {
        anyhow::ensure!(
            args.scrollback <= MAX_SCROLLBACK,
            "scrollback {} exceeds the maximum of {MAX_SCROLLBACK}",
            args.scrollback
        );
        anyhow::ensure!(args.max_sessions >= 1, "max_sessions must be at least 1");
        let allow: HashSet<EndpointId> = args.allow.iter().copied().collect();
        if allow.is_empty() {
            anyhow::bail!(
                "no clients authorized: pass --allow <endpoint-id> (repeatable; get one from `koh id`)"
            );
        }
        anyhow::ensure!(
            args.max_connections >= 1,
            "max_connections must be at least 1"
        );
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
            launcher: args.launcher.clone(),
        })
    }
}

/// Serve the allowed clients on `endpoint` until `shutdown` is cancelled or it closes, then close
/// it: `koh serve`'s accept loop, which tests run on their own transports.
pub async fn serve_endpoint(
    endpoint: iroh::Endpoint,
    hosting: Hosting,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    let allow = Arc::new(hosting.allow);
    let registry = Registry::spawn(SessionSpec {
        command: hosting.command,
        scrollback: hosting.scrollback,
        max_sessions: hosting.max_sessions,
        ttl: hosting.session_ttl,
        launcher: hosting.launcher,
    });

    // Each connection holds a permit for its life; past the cap a dial is refused before its
    // handshake, which is cheap.
    let conn_limit = Arc::new(tokio::sync::Semaphore::new(hosting.max_connections));
    // A smaller cap on connections not yet admitted, so peers that stall their handshakes cannot
    // hold every connection permit. Admission releases it.
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
        // Admission, in order: a connection permit, a pending-handshake permit, the handshake within
        // its deadline, the allowlist (the handshake authenticated the peer's id), then the admission
        // ack and the session.
        let Ok(permit) = conn_limit.clone().try_acquire_owned() else {
            warn!("refusing connection: at max-connections capacity");
            incoming.refuse();
            continue;
        };
        let Ok(pending_permit) = handshake_limit.clone().try_acquire_owned() else {
            warn!("refusing connection: too many handshakes in flight");
            incoming.refuse();
            continue;
        };
        let allow = allow.clone();
        let sessions = registry.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let pending_permit = pending_permit;
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
            drop(pending_permit);
            serve_connection(conn, &sessions).await;
        });
    }

    // Sessions first, then the endpoint.
    info!("draining: stopping the registry and closing endpoint");
    shutdown.cancel();
    registry.shutdown().await;
    if !crate::transport_iroh::close_endpoint(&endpoint).await {
        warn!("peers did not see the endpoint close in time; exiting anyway");
    }
    Ok(())
}

/// Serve one allowed connection: send the admission ack, then attach its peer's session and drive
/// it; returning detaches.
async fn serve_connection(conn: iroh::endpoint::Connection, registry: &Registry) {
    let peer = conn.remote_id();
    // Bounded, so a client that never accepts the stream cannot hold its slot.
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

    let Some((client, attach_kind)) = registry.attach(peer).await else {
        // At the session cap, which only a new peer can hit.
        warn!(peer = %peer, "refusing session: at max-sessions capacity");
        conn.close(1u32.into(), b"server at session capacity");
        return;
    };
    match attach_kind {
        AttachKind::Created => {
            info!(peer = %peer, "started a new session");
        }
        AttachKind::Reattached { detached_for } => {
            info!(
                peer = %peer,
                detached_secs = detached_for.map(|d| d.as_secs()),
                "reattaching to this peer's existing session"
            );
        }
    }
    match run_attached(conn, client).await {
        Ok(SessionExit::Detached) => {
            info!(peer = %peer, "client detached (session retained)");
        }
        Ok(SessionExit::ShellExited) => {
            info!(peer = %peer, "shell exited");
        }
        Err(e) => error!(error = %e, "session loop error"),
    }
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
