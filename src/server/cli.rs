//! The `koh serve` command.
//!
//! Binds an iroh endpoint with a persistent identity, authorizes incoming clients against a
//! node-id allowlist, and for each accepted connection runs a PTY-backed shell whose screen is
//! kept in sync with the client via the SSP over QUIC datagrams (`Transport<TerminalScreen,
//! UserInput>`). [`serve_with`] generalizes this to any [`SessionHost`] behind a [`HostProvider`],
//! one per ALPN (KH-01, KH-02).
//!
//! Auth model (deliberately *not* iroh-ssh's "anyone with the endpoint id gets a shell"):
//! a connection is only served if the client's endpoint id is on the `--allow` list. There is no
//! "accept any peer" escape hatch — an allowlist entry is the sole way in.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
#[cfg(feature = "cli")]
use clap::Args as ClapArgs;
use iroh::EndpointId;
use tokio::signal::unix::{signal, SignalKind};
use tokio_util::sync::CancellationToken;

use crate::server::audit::{auth_event, Outcome};
use crate::server::session::{ClientId, HostProvider, PtyHosts, SessionHost};
use crate::server::{run_attached, session, SessionExit};
use crate::transport_iroh::{
    bind_endpoint_alpns, bind_endpoint_local_alpns, bind_endpoint_with_relay_alpns,
    format_endpoint_id, parse_endpoint_id, parse_relay_url, TERMINAL_ALPN,
};
use tracing::{error, info, warn};

/// Deadline on the QUIC crypto handshake (`Incoming::await`) before a stalled dial is dropped and
/// its connection + pending-handshake permits released (KR-01). A legitimate 1-RTT QUIC handshake
/// finishes in well under this even on a slow mobile link; the cap exists so a peer can't pin a
/// pending slot for the 300s idle timeout koh configures (`koh_transport_config`).
const ACCEPT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Configuration for [`serve`] — the clap-free, library-facing form of `koh serve`'s arguments.
///
/// Every field is public so an embedding binary can build one directly (see the crate docs on
/// library use). The `koh` binary builds it from [`ServeArgs`] via `From`. [`Default`] gives the
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
pub const MAX_SCROLLBACK: u64 = 1_000_000;

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

/// Arguments for `koh serve` (the clap adapter over [`ServeConfig`]; `cli` feature only).
#[cfg(feature = "cli")]
#[derive(ClapArgs, Debug)]
pub struct ServeArgs {
    /// Path to the persistent secret-key file (gives a stable endpoint id across restarts).
    #[arg(long)]
    key_file: Option<PathBuf>,

    /// Authorize a client endpoint id (repeatable). At least one is required — koh only serves
    /// peers whose node-id is on this list.
    #[arg(long = "allow", value_name = "ENDPOINT_ID")]
    allow: Vec<String>,

    /// Program to run in the session (defaults to the user's login shell). Repeat to pass
    /// arguments: `--shell zellij --shell attach --shell -c --shell main` runs
    /// `zellij attach -c main`. The value is never split on whitespace.
    #[arg(long, value_name = "PROGRAM_OR_ARG")]
    shell: Vec<String>,

    /// Scrollback lines retained by the server-side emulator (per session). Bounded like the other
    /// resource knobs (`--max-connections`/`--max-sessions`): vt100 allocates the grid eagerly, so an
    /// unbounded value × `--max-sessions` is a memory footgun. 0 = no scrollback.
    #[arg(long, default_value_t = DEFAULT_SCROLLBACK, value_parser = clap::value_parser!(u64).range(0..=MAX_SCROLLBACK))]
    scrollback: u64,

    /// Keep a detached session's shell alive this long (seconds) for the client to reconnect.
    /// Default 24h (mosh-style "close the laptop, reopen later").
    #[arg(long, default_value_t = DEFAULT_SESSION_TTL_SECS)]
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
    #[arg(long, default_value_t = DEFAULT_MAX_CONNECTIONS, value_parser = clap::value_parser!(u32).range(1..))]
    max_connections: u32,

    /// Maximum number of distinct live sessions (one per authorized peer). A new peer is refused
    /// once this many sessions exist; reconnecting to an existing session is always allowed. Bounds
    /// the number of real shells a flood of authorized keys can spawn.
    #[arg(long, default_value_t = DEFAULT_MAX_SESSIONS, value_parser = clap::value_parser!(u32).range(1..))]
    max_sessions: u32,
}

#[cfg(feature = "cli")]
impl From<ServeArgs> for ServeConfig {
    fn from(a: ServeArgs) -> Self {
        Self {
            key_file: a.key_file,
            allow: a.allow,
            command: a.shell,
            scrollback: a.scrollback,
            session_ttl_secs: a.session_ttl_secs,
            relay_url: a.relay_url,
            local: a.local,
            max_connections: a.max_connections,
            max_sessions: a.max_sessions,
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
/// [`ServeConfig`] or anything convertible into one ([`ServeArgs`] under the `cli` feature).
///
/// Installs a global `tracing` subscriber writing to stderr if none is installed yet. This is
/// [`serve_with`] over a [`PtyHosts`] provider on [`TERMINAL_ALPN`].
pub async fn serve(config: impl Into<ServeConfig>) -> anyhow::Result<()> {
    let args: ServeConfig = config.into();
    // `try_init`, not `init`: an embedding binary may already own a subscriber (KH-01).
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
    // The CLI enforces this range in clap; a library caller bypasses that, so re-check here.
    anyhow::ensure!(
        args.scrollback <= MAX_SCROLLBACK,
        "scrollback {} exceeds the maximum of {MAX_SCROLLBACK}",
        args.scrollback
    );
    anyhow::ensure!(args.max_sessions >= 1, "max_sessions must be at least 1");
    // Cast the validated u64 (range 0..=MAX_SCROLLBACK) down to the usize the emulator wants.
    let provider = PtyHosts::new(
        args.command.clone(),
        args.scrollback as usize,
        args.max_sessions as usize,
    );
    serve_with(args, Hosts::new().with(TERMINAL_ALPN, provider)).await
}

/// One ALPN-keyed provider with its host type erased (KH-02).
///
/// Lets [`Hosts`] hold providers for several state types in one list.
trait ErasedProvider: Send + Sync {
    /// Attach `peer`'s admitted connection to a session, drive it, and release it afterwards.
    fn serve_conn(
        &self,
        conn: iroh::endpoint::Connection,
        peer: EndpointId,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>>;

    /// Start this provider's TTL reaper.
    fn spawn_reaper(
        &self,
        ttl: Duration,
        interval: Duration,
        shutdown: CancellationToken,
    ) -> tokio::task::JoinHandle<()>;
}

struct Typed<H, P> {
    provider: Arc<P>,
    _host: std::marker::PhantomData<fn() -> H>,
}

impl<H: SessionHost, P: HostProvider<H>> ErasedProvider for Typed<H, P> {
    fn serve_conn(
        &self,
        conn: iroh::endpoint::Connection,
        peer: EndpointId,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            // Attach to (or create) this client's detachable session, then serve the connection.
            let (handle, attach_kind) = match self.provider.attach(peer).await {
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
                session::AttachKind::Joined { viewers } => {
                    info!(
                        peer = %format_endpoint_id(&peer),
                        viewers,
                        "joined the shared session"
                    );
                }
            }
            let client = ClientId::next();
            // Arm a RAII safety net BEFORE serving: if `run_attached` unwinds (panics), the guard's
            // Drop still releases this connection's session attach through the provider so it
            // can't leak, shared hosts included (K-16, KS-04). On a normal return we disarm and
            // run the precise detach/reap below ourselves.
            let attach_guard = session::AttachGuard::new(self.provider.clone(), peer);
            let outcome = run_attached(conn, handle.clone(), client).await;
            attach_guard.disarm();
            handle.session.lock().await.host.client_detached(client);
            match outcome {
                Ok(SessionExit::Detached) => {
                    // Keep the host running for reattach.
                    self.provider.detach(peer).await;
                    info!(peer = %format_endpoint_id(&peer), "client detached (session retained)");
                }
                Ok(SessionExit::ShellExited) => {
                    self.provider.reap(peer).await;
                    info!(peer = %format_endpoint_id(&peer), "shell exited; session reaped");
                }
                Err(e) => {
                    error!(error = %e, "session loop error");
                    self.provider.detach(peer).await;
                }
            }
        })
    }

    fn spawn_reaper(
        &self,
        ttl: Duration,
        interval: Duration,
        shutdown: CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(session::run_reaper(
            self.provider.store(),
            ttl,
            interval,
            shutdown,
        ))
    }
}

/// The set of state types a server offers, one [`HostProvider`] per ALPN (KH-02).
///
/// `Hosts::new().with(TERMINAL_ALPN, PtyHosts::new(..)).with(b"my/state/1", SharedHost::new(..))`
/// serves both on one endpoint; the accepted connection's negotiated ALPN selects the provider.
#[derive(Default)]
pub struct Hosts {
    entries: Vec<(Vec<u8>, Arc<dyn ErasedProvider>)>,
}

impl Hosts {
    pub fn new() -> Self {
        Self::default()
    }

    /// Serve `provider`'s state type to connections negotiating `alpn`.
    #[must_use]
    pub fn with<H: SessionHost, P: HostProvider<H>>(mut self, alpn: &[u8], provider: P) -> Self {
        self.entries.push((
            alpn.to_vec(),
            Arc::new(Typed::<H, P> {
                provider: Arc::new(provider),
                _host: std::marker::PhantomData,
            }),
        ));
        self
    }

    /// The ALPNs to bind the endpoint with.
    pub fn alpns(&self) -> Vec<Vec<u8>> {
        self.entries.iter().map(|(a, _)| a.clone()).collect()
    }

    fn for_alpn(&self, alpn: &[u8]) -> Option<Arc<dyn ErasedProvider>> {
        self.entries
            .iter()
            .find(|(a, _)| a == alpn)
            .map(|(_, p)| p.clone())
    }

    /// Serve one already-authorized connection: pick the provider for its negotiated ALPN, send
    /// the admission ack, attach, drive, release. For embedding servers (and tests) that own
    /// their accept loop and allowlist; [`serve_with`] calls this after its admission gauntlet.
    pub async fn serve_connection(&self, conn: iroh::endpoint::Connection) {
        let peer = conn.remote_id();
        // The negotiated ALPN picks the state type (KH-02). iroh only completes the handshake
        // for an ALPN in the bound list, so a miss here is a programming error, not a peer one.
        let Some(provider) = self.for_alpn(conn.alpn()) else {
            error!(alpn = %String::from_utf8_lossy(conn.alpn()), "no host provider for negotiated alpn");
            conn.close(1u32.into(), b"no host for alpn");
            return;
        };
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
        auth_event(Outcome::Accepted, &peer, "authorized; attaching session");
        provider.serve_conn(conn, peer).await;
    }
}

/// Serve any set of hosts (KH-01, KH-02).
///
/// Binds the endpoint on the ALPNs in `hosts`, authorizes peers against `config.allow`, and for
/// each admitted connection attaches it to the provider for its negotiated ALPN. `config.command`,
/// `scrollback` and `max_sessions` are not read here (they belong to the [`PtyHosts`] provider);
/// the caller owns tracing.
pub async fn serve_with(config: impl Into<ServeConfig>, hosts: Hosts) -> anyhow::Result<()> {
    let args: ServeConfig = config.into();
    anyhow::ensure!(
        !hosts.entries.is_empty(),
        "serve_with needs at least one host"
    );

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
    // The CLI enforces these ranges in clap; a library caller bypasses that, so re-check here.
    anyhow::ensure!(
        args.max_connections >= 1,
        "max_connections must be at least 1"
    );

    let key_file = match args.key_file.clone() {
        Some(p) => p,
        None => crate::transport_iroh::default_key_path("server")?,
    };
    let identity = crate::identity::load(&key_file)?;
    let secret = identity.secret.clone();

    // Pick the network profile: self-hosted relay, relay-less LAN/loopback, or default n0.
    let alpns = hosts.alpns();
    let endpoint = if let Some(url) = &args.relay_url {
        let relay = parse_relay_url(url)?;
        bind_endpoint_with_relay_alpns(secret, alpns, relay)
            .await
            .context("binding endpoint")?
    } else if args.local {
        bind_endpoint_local_alpns(secret, alpns)
            .await
            .context("binding endpoint")?
    } else {
        bind_endpoint_alpns(secret, alpns)
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
    eprintln!(
        "│ alpn        : {}",
        hosts
            .entries
            .iter()
            .map(|(a, _)| String::from_utf8_lossy(a).into_owned())
            .collect::<Vec<_>>()
            .join(", ")
    );
    eprintln!("│ auth        : allowlist ({} client(s))", allow.len());
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

    let allow = std::sync::Arc::new(allow);
    let hosts = Arc::new(hosts);

    // Detachable session stores: one per provider, surviving disconnects so a reconnecting client
    // lands back in the same session at the current state. Each reaper collects sessions whose
    // program exited or that have been detached past the TTL.
    let session_ttl = Duration::from_secs(args.session_ttl_secs);
    let reaper_shutdown = tokio_util::sync::CancellationToken::new();
    let reapers: Vec<_> = hosts
        .entries
        .iter()
        .map(|(_, p)| p.spawn_reaper(session_ttl, session::REAP_INTERVAL, reaper_shutdown.clone()))
        .collect();

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
        let hosts = hosts.clone();
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
            hosts.serve_connection(conn).await;
        });
    }

    // The accept loop ended (endpoint closed or a shutdown signal): stop the reapers cleanly and
    // wait for them to finish their current sweep before tearing down the endpoint.
    info!("draining: stopping reaper and closing endpoint");
    shutdown.cancel();
    reaper_shutdown.cancel();
    for r in reapers {
        let _ = r.await;
    }
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

    #[cfg(feature = "cli")]
    #[test]
    fn serve_args_map_shell_to_command_argv_and_keep_defaults() {
        use clap::Parser;
        #[derive(Parser)]
        struct Cli {
            #[command(flatten)]
            serve: ServeArgs,
        }
        let cli = Cli::parse_from([
            "koh", "--allow", "abc", "--shell", "zellij", "--shell", "attach",
        ]);
        let c: ServeConfig = cli.serve.into();
        assert_eq!(c.command, ["zellij", "attach"]);
        assert_eq!(c.allow, ["abc"]);
        // Everything not given on the command line must equal `ServeConfig::default()`.
        let d = ServeConfig::default();
        assert_eq!(c.scrollback, d.scrollback);
        assert_eq!(c.session_ttl_secs, d.session_ttl_secs);
        assert_eq!(c.max_connections, d.max_connections);
        assert_eq!(c.max_sessions, d.max_sessions);

        // A single `--shell` is still just the program, as before.
        let cli = Cli::parse_from(["koh", "--allow", "abc", "--shell", "/bin/zsh"]);
        assert_eq!(ServeConfig::from(cli.serve).command, ["/bin/zsh"]);
        // No `--shell` = login shell.
        let cli = Cli::parse_from(["koh", "--allow", "abc"]);
        assert!(ServeConfig::from(cli.serve).command.is_empty());
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
