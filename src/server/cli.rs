//! The `koh serve` command: bind an endpoint with a persistent identity, admit only the clients on
//! the `--allow` list, and host each one's session. There is no "accept any peer" mode.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use iroh::{EndpointId, RelayUrl};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use crate::bounded::Bounded;
use crate::identity::KeyFile;
use crate::log::Peer;
use crate::names::List;
use crate::proto::Close;
use crate::server::audit::{auth_event, Outcome};
use crate::server::run_attached;
use crate::server::session::{AttachKind, Registry, SessionSpec};
use crate::transport_iroh::{bind_on, close, Network, PROTOCOL};
use tracing::{debug, info, warn};

/// Deadline on the QUIC handshake, so a stalled dial cannot hold its permits for the 5-minute idle
/// timeout; a real handshake takes far less, even on a slow mobile link.
const ACCEPT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The clap-free form of `koh serve`'s arguments. [`Default`] gives the CLI's defaults, with an
/// empty `allow`, which [`serve`] rejects.
#[derive(Debug, Clone)]
pub struct ServeConfig {
    /// The secret-key file; `None` for the default server key path.
    pub key_file: Option<PathBuf>,
    /// The client endpoint ids allowed in for this run, beside `saved_clients`; at least one
    /// client between them.
    pub allow: Vec<EndpointId>,
    /// Where the clients saved with `koh clients add` are, read again every [`REVOKE_CHECK`];
    /// `None` for none.
    pub saved_clients: Option<crate::names::Places>,
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
    /// The UDP port to bind (IPv4 and IPv6); `None` for ephemeral ports. A fixed port lets a client
    /// dialing `--direct <ip:port>` redial a restarted server.
    pub port: Option<u16>,
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
            saved_clients: None,
            command: Vec::new(),
            scrollback: DEFAULT_SCROLLBACK,
            session_ttl_secs: DEFAULT_SESSION_TTL_SECS,
            relay_url: None,
            local: false,
            port: None,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            max_sessions: DEFAULT_MAX_SESSIONS,
            launcher: crate::pty::Launcher::this_binary(),
        }
    }
}

/// `data` as a QR code for a dark-background terminal (dark modules drawn as the background, so a
/// camera reads dark on light), or `None` if it is too large to encode.
pub fn connect_qr(data: &str) -> Option<String> {
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
    crate::log::init_stderr(tracing::Level::INFO);
    // Before the banner, so a signal once it shows is handled.
    let shutdown = CancellationToken::new();
    let forced = crate::cancel_on_signals(&shutdown).context("installing the signal handlers")?;
    let hosting = Hosting::from_config(&args)?;

    let key_file = crate::identity::KeyFile::locate(args.key_file.clone(), "server")?;
    let identity = crate::identity::load(&key_file)?;
    let secret = identity.secret.clone();

    // Pick the network profile: self-hosted relay, relay-less LAN/loopback, or default n0.
    let network = match (&args.relay_url, args.local) {
        (Some(relay), _) => Network::Relay(relay.clone()),
        (None, true) => Network::Local,
        (None, false) => Network::N0,
    };
    let endpoint = bind_on(secret, true, &network, args.port)
        .await
        .context("binding endpoint")?;
    let my_id = endpoint.id();
    let id_str = my_id.to_string();
    let port = endpoint
        .bound_sockets()
        .iter()
        .find(|s| s.is_ipv4())
        .map_or(0, std::net::SocketAddr::port);

    // How a client should dial us, given the chosen profile.
    let connect_hint = match &network {
        Network::Relay(url) => format!("koh connect {id_str} --relay-url {url}"),
        Network::Local => format!("koh connect {id_str} --direct <this-host-ip>:{port}"),
        Network::N0 => format!("koh connect {id_str}"),
    };
    let port_note = if args.port.is_some() {
        String::new()
    } else {
        " (ephemeral; --port fixes it across restarts)".to_owned()
    };

    let clients = hosting.allowed.len();
    // A phone camera can read the id instead of anyone copying 64 hex digits.
    let qr = connect_qr(&id_str).map_or_else(
        || {
            warn!("could not render the connect QR (endpoint id too large to encode)");
            String::new()
        },
        |qr| {
            format!(
                "\nScan for the endpoint id (point a phone camera at it). Assumes a \
                 dark-background terminal;\non a light background it renders inverted — copy \
                 the id above instead:\n\n{qr}\n"
            )
        },
    );
    let banner = format!(
        "┌─ koh server ready ──────────────────────────────────────\n\
         │ endpoint id : {id_str}\n\
         │ key file    : {key_file}\n\
         │ alpn        : {PROTOCOL}\n\
         │ auth        : allowlist ({clients} client(s))\n\
         │ udp port    : {port}{port_note}\n\
         │ connect     : {connect_hint}\n\
         └───────────────────────────────────────────────────────────\n{qr}"
    );
    crate::log::stderr(banner.trim_end());

    // What protects the link, iroh's choice: so an operator sees post-quantum KEX is not on.
    info!(
        transport = "QUIC + TLS 1.3 (iroh)",
        kex = "X25519",
        post_quantum = false,
        "transport crypto posture"
    );

    tokio::select! {
        served = serve_endpoint(endpoint, hosting, shutdown) => served,
        () = forced.cancelled() => {
            anyhow::bail!("another signal: exiting without waiting for the sessions to end")
        }
    }
}

/// How often the saved clients are read again: one removed from them is cut off, its session
/// ended, within this.
pub const REVOKE_CHECK: Duration = Duration::from_secs(2);

/// Who may connect: the ids given for this run, and the clients saved beside the server key.
pub struct Allowlist {
    given: HashSet<EndpointId>,
    /// The key the saved list sits beside, its directory judged once, and the list's path for
    /// messages.
    saved: Option<(KeyFile, String)>,
}

/// Who may connect now, as [`watch_allowlist`] publishes it, never an error; and a way to have it
/// read at once, for a peer not on it yet (one `koh clients add` just saved).
#[derive(Clone)]
struct Gate {
    allowed: watch::Receiver<Arc<HashSet<EndpointId>>>,
    reread: tokio::sync::mpsc::Sender<tokio::sync::oneshot::Sender<()>>,
}

impl Gate {
    /// Whether `peer` may connect: on the list, or on it once it is read again.
    async fn allows(&self, peer: EndpointId) -> bool {
        if self.allowed.borrow().contains(&peer) {
            return true;
        }
        let (read, done) = tokio::sync::oneshot::channel();
        if self.reread.send(read).await.is_ok() {
            let _ = done.await;
        }
        self.allowed.borrow().contains(&peer)
    }

    /// Return once `peer` is no longer allowed. Never if the list stops being published: the
    /// server is then shutting down, which ends the connection anyway.
    async fn revoked(mut self, peer: EndpointId) {
        if self
            .allowed
            .wait_for(|now| !now.contains(&peer))
            .await
            .is_err()
        {
            std::future::pending::<()>().await;
        }
    }
}

impl Allowlist {
    /// The clients who may connect as the saved list says now.
    fn read(&self) -> anyhow::Result<HashSet<EndpointId>> {
        let mut allowed = self.given.clone();
        if let Some((key, shown)) = &self.saved {
            let saved = crate::names::read(key, List::Clients, shown)?;
            allowed.extend(saved.entries().map(|(_, id)| id));
        }
        Ok(allowed)
    }
}

/// A value replaced only by a successful read: a list that cannot be read (a typo, an editor
/// writing it in place) is not an empty one, and locks no one out.
struct LastGood<T> {
    value: T,
    /// The last read failed, and said so.
    failing: bool,
}

impl<T: PartialEq> LastGood<T> {
    /// Take what a read gave; whether the value changed. A failure keeps the last value, and is
    /// warned of once until a read succeeds again.
    fn update(&mut self, read: anyhow::Result<T>) -> bool {
        let failed = read.as_ref().err().map(|e| format!("{e:#}"));
        if let Some(error) = failed.filter(|_| !std::mem::replace(&mut self.failing, true)) {
            warn!(%error, "could not read the saved clients; keeping the list last read");
        }
        let Ok(value) = read else { return false };
        self.failing = false;
        std::mem::replace(&mut self.value, value) != self.value
    }
}

/// Read `list` every [`REVOKE_CHECK`], and at once when asked on `reread` (answering once it is
/// read), publishing each change on `allowed`, until no one watches; and end in `registry` the
/// session of each peer a change drops, connected or not. The one reader of the list.
async fn watch_allowlist(
    list: Allowlist,
    allowed: watch::Sender<Arc<HashSet<EndpointId>>>,
    mut reread: tokio::sync::mpsc::Receiver<tokio::sync::oneshot::Sender<()>>,
    registry: Registry,
) {
    let list = Arc::new(list);
    let mut last = LastGood {
        value: allowed.borrow().clone(),
        failing: false,
    };
    loop {
        let mut asked = Vec::new();
        tokio::select! {
            () = allowed.closed() => return,
            () = tokio::time::sleep(REVOKE_CHECK) => {}
            Some(ask) = reread.recv() => asked.push(ask),
        }
        // Every ask made before this read is answered by it; one made during it, by the next.
        while let Ok(ask) = reread.try_recv() {
            asked.push(ask);
        }
        let reading = Arc::clone(&list);
        let read = tokio::task::spawn_blocking(move || reading.read())
            .await
            .map_err(anyhow::Error::from)
            .and_then(|read| read.map(Arc::new));
        let before = Arc::clone(&last.value);
        if last.update(read) {
            allowed.send_replace(Arc::clone(&last.value));
            for gone in before.difference(&last.value) {
                registry.end(*gone).await;
            }
        }
        for ask in asked {
            let _ = ask.send(());
        }
    }
}

/// A connection whose peer the allowlist admitted: the only kind a session is served to, and made
/// only by the accept loop, after the allowlist.
pub struct Authorized(iroh::endpoint::Connection);

impl Authorized {
    /// The connection.
    pub const fn conn(&self) -> &iroh::endpoint::Connection {
        &self.0
    }
}

/// A validated [`ServeConfig`]: who may connect, what each session runs, and the limits.
pub struct Hosting {
    allow: Allowlist,
    /// Who may connect, as first read.
    allowed: HashSet<EndpointId>,
    spec: SessionSpec,
    max_connections: usize,
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
        let saved = args
            .saved_clients
            .as_ref()
            .map(|places| {
                let key = KeyFile::open(places.key(List::Clients.role()))?;
                anyhow::Ok((key, crate::names::shown(places, List::Clients)))
            })
            .transpose()?;
        let allow = Allowlist {
            given: args.allow.iter().copied().collect(),
            saved,
        };
        let allowed = allow.read()?;
        if allowed.is_empty() {
            anyhow::bail!(
                "no clients authorized: save one with `koh clients add <name> <endpoint-id>`, or pass --allow <endpoint-id> (get it from `koh id` on the client)"
            );
        }
        anyhow::ensure!(
            args.max_connections >= 1,
            "max_connections must be at least 1"
        );
        Ok(Self {
            allow,
            allowed,
            spec: SessionSpec {
                command: args.command.clone().into(),
                scrollback: usize::try_from(args.scrollback)
                    .context("scrollback does not fit in usize")?,
                max_sessions: usize::try_from(args.max_sessions)
                    .context("max_sessions does not fit in usize")?,
                ttl: Duration::from_secs(args.session_ttl_secs),
                launcher: args.launcher.clone(),
            },
            max_connections: usize::try_from(args.max_connections)
                .context("max_connections does not fit in usize")?,
        })
    }
}

/// Where a handshake comes from, for the cap on each: an IPv4 address, or an IPv6 /64 (one host's
/// share). `None` through a relay, where an address says nothing.
fn source(addr: &iroh::endpoint::IncomingAddr) -> Option<std::net::IpAddr> {
    let iroh::endpoint::IncomingAddr::Ip(at) = addr else {
        return None;
    };
    Some(match at.ip() {
        std::net::IpAddr::V6(v6) => {
            std::net::Ipv6Addr::from(u128::from(v6) & !u128::from(u64::MAX)).into()
        }
        v4 @ std::net::IpAddr::V4(_) => v4,
    })
}

/// Most handshakes one address has under way at once; past them its next is refused.
const PER_SOURCE: usize = 2;

/// Most handshakes under way at once, whatever the connection limit.
const MOST_PENDING: usize = 256;

/// The handshakes under way, oldest first, each with its address and its handle `H`: at most
/// [`PER_SOURCE`] from one address, that address's oldest given up for a new one, and at most
/// `cap` in all, the oldest given up (one through a relay has no address, so only `cap` holds it).
/// Anyone who can reach the port can start handshakes and stall them; this way a new handshake is
/// never refused, so an allowed client's dial, which finishes in a round trip, gets through a
/// flood, even one from its own address (the same host, a shared NAT).
struct Pending<H> {
    cap: usize,
    under_way: Bounded<(Option<std::net::IpAddr>, H), MOST_PENDING>,
}

impl<H> Pending<H> {
    /// Room for a handshake from `source`, those `done` forgotten: the handshake given up for it,
    /// if any, its address's oldest when it has its share under way, else the oldest of all when
    /// all the room is taken.
    fn room(&mut self, source: Option<std::net::IpAddr>, done: impl Fn(&H) -> bool) -> Option<H> {
        self.under_way.retain(|(_, handle)| !done(handle));
        let from = self.under_way.iter().filter(|(s, _)| *s == source).count();
        let given_up = if source.is_some() && from >= PER_SOURCE {
            self.under_way.take_first(|(s, _)| *s == source)
        } else if self.under_way.len() >= self.cap {
            self.under_way.pop_front()
        } else {
            None
        };
        given_up.map(|(_, oldest)| oldest)
    }
}

/// Serve the allowed clients on `endpoint` until `shutdown` is cancelled or it closes, then close
/// it: `koh serve`'s accept loop, which tests run on their own transports.
pub async fn serve_endpoint(
    endpoint: iroh::Endpoint,
    hosting: Hosting,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    let registry = Registry::spawn(hosting.spec).context("starting the child reaper")?;
    let (allowed_tx, allowed) = watch::channel(Arc::new(hosting.allowed));
    let (reread, asks) = tokio::sync::mpsc::channel(64);
    let gate = Gate { allowed, reread };
    #[expect(clippy::disallowed_methods, reason = "one allowlist reader a server")]
    tokio::spawn(watch_allowlist(
        hosting.allow,
        allowed_tx,
        asks,
        registry.clone(),
    ));

    // Each connection holds a permit for its life; past the cap a dial is refused before its
    // handshake, which is cheap.
    let conn_limit = Arc::new(tokio::sync::Semaphore::new(hosting.max_connections));
    // A smaller cap on handshakes under way, so stalled ones cannot hold every connection permit:
    // below the total, unless it is 1.
    let mut pending = Pending {
        cap: hosting
            .max_connections
            .div_ceil(4)
            .max(4)
            .min(hosting.max_connections.saturating_sub(1))
            .clamp(1, MOST_PENDING),
        under_way: Bounded::new(),
    };
    // A flood is warned of at most once every 10 s.
    let mut warned: Option<std::time::Instant> = None;

    loop {
        let incoming = tokio::select! {
            biased;
            () = shutdown.cancelled() => break,
            inc = endpoint.accept() => match inc {
                Some(i) => i,
                None => break, // endpoint closed
            },
        };
        // In order: a connection permit, room for a handshake, the handshake within its deadline,
        // the allowlist (the handshake authenticated the peer's id), the session, then the
        // admission ack.
        let Ok(permit) = conn_limit.clone().try_acquire_owned() else {
            warn!("refusing connection: at max-connections capacity");
            incoming.refuse();
            continue;
        };
        let source = source(&incoming.remote_addr());
        let given_up = pending.room(source, tokio::task::AbortHandle::is_finished);
        let now = std::time::Instant::now();
        if given_up.is_some()
            && warned.is_none_or(|at| now.saturating_duration_since(at) >= Duration::from_secs(10))
        {
            warned = Some(now);
            warn!("too many handshakes in flight: giving up the oldest for new ones");
        }
        given_up.iter().for_each(tokio::task::AbortHandle::abort);
        let (gate, sessions) = (gate.clone(), registry.clone());
        #[expect(
            clippy::disallowed_methods,
            reason = "a handshake under way, at most `pending.cap`, then a task a connection, each \
                      holding a permit"
        )]
        let handshake = tokio::spawn(async move {
            match tokio::time::timeout(ACCEPT_HANDSHAKE_TIMEOUT, incoming).await {
                Ok(Ok(conn)) => drop(tokio::spawn(admit(conn, gate, sessions, permit))),
                // Anyone can start one: said quietly, as a flood would say it often.
                Ok(Err(e)) => debug!(error = %Peer(e), "incoming handshake failed"),
                Err(_) => debug!("incoming handshake timed out (a stalled QUIC handshake)"),
            }
        });
        pending
            .under_way
            .push_evicting((source, handshake.abort_handle()));
    }

    // Sessions first, with their programs reaped (or killed after their grace), then the endpoint.
    info!("draining: stopping the registry and closing endpoint");
    shutdown.cancel();
    registry.shutdown().await;
    if !crate::transport_iroh::close_endpoint(&endpoint).await {
        warn!("peers did not see the endpoint close in time; exiting anyway");
    }
    Ok(())
}

/// Admit `conn` if its peer is allowed, then serve it until it detaches, or the peer is removed
/// from the list, which ends its session too. Holds `permit` throughout.
async fn admit(
    conn: iroh::endpoint::Connection,
    gate: Gate,
    registry: Registry,
    permit: tokio::sync::OwnedSemaphorePermit,
) {
    let _permit = permit;
    let peer = conn.remote_id();
    if !gate.allows(peer).await {
        auth_event(Outcome::Rejected, &peer, "not on allowlist");
        close(&conn, Close::NotAuthorized);
        return;
    }
    tokio::select! {
        () = serve_connection(Authorized(conn.clone()), &registry) => {}
        () = gate.revoked(peer) => {
            auth_event(Outcome::Rejected, &peer, "removed from the allowlist");
            close(&conn, Close::NotAuthorized);
        }
    }
}

/// Serve one allowed connection: attach its peer's session, send the admission ack, then drive
/// it; returning detaches. The ack waits for the session, so a client is admitted only to one.
async fn serve_connection(authorized: Authorized, registry: &Registry) {
    let conn = authorized.conn();
    let peer = conn.remote_id();
    let (client, attach_kind) = match registry.attach(peer).await {
        Ok(attached) => attached,
        Err(refused) => {
            warn!(peer = %peer, reason = %refused, "refusing session");
            close(conn, refused);
            return;
        }
    };
    // Bounded, so a client that never accepts the stream cannot hold its slot.
    match tokio::time::timeout(
        Duration::from_secs(3),
        crate::transport_iroh::admission::admit(conn),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            warn!(error = %Peer(e), "admission ack failed");
            return;
        }
        Err(_) => {
            warn!("admission ack timed out");
            return;
        }
    }
    auth_event(Outcome::Accepted, &peer, "authorized; session attached");
    match attach_kind {
        AttachKind::Created => info!(peer = %peer, "started a new session"),
        AttachKind::Reattached { detached_for } => info!(
            peer = %peer,
            detached_secs = detached_for.map(|d| d.as_secs()),
            "reattaching to this peer's existing session"
        ),
    }
    run_attached(authorized, client).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_saved_list_that_cannot_be_read_keeps_the_last_one() {
        let dir = crate::test_runtime::scratch("last-good");
        let places = crate::names::Places::new(None, Some(dir.join("server.key"))).unwrap();
        let client = crate::transport_iroh::generate_secret_key()
            .unwrap()
            .public();
        let clients = dir.join("clients");
        std::fs::write(&clients, format!("laptop {client}\n")).unwrap();
        let hosting = Hosting::from_config(&ServeConfig {
            saved_clients: Some(places),
            ..ServeConfig::default()
        })
        .unwrap();
        let mut last = LastGood {
            value: hosting.allowed,
            failing: false,
        };
        // A typo while editing it: everyone saved stays allowed.
        std::fs::write(&clients, format!("laptop {client} oops\n")).unwrap();
        assert!(!last.update(hosting.allow.read()));
        assert!(last.value.contains(&client) && last.failing);
        // Removed for real: gone.
        std::fs::write(&clients, "# nobody\n").unwrap();
        assert!(last.update(hosting.allow.read()));
        assert!(!last.value.contains(&client) && !last.failing);
    }

    #[test]
    fn a_handshake_flood_cannot_take_an_allowed_clients_room() {
        type Handshakes = Pending<u8>;
        /// A handshake from `from`'s address, numbered `n`: the one given up for it, if any.
        /// Handshake 99, the allowed client's, finishes as soon as it is under way.
        fn begin(pending: &mut Handshakes, from: u8, n: u8) -> Option<u8> {
            let source = Some(std::net::IpAddr::from([203, 0, 113, from]));
            let given_up = pending.room(source, |&h| h == 99);
            pending.under_way.push_evicting((source, n));
            given_up
        }
        let mut pending = Pending {
            cap: 4,
            under_way: Bounded::new(),
        };
        // One address holds only its share: a third gives up its own oldest, no one else's.
        assert_eq!(begin(&mut pending, 1, 1), None);
        assert_eq!(begin(&mut pending, 1, 2), None);
        assert_eq!(begin(&mut pending, 1, 3), Some(1));
        // Many fill the rest; then each new handshake gives up the oldest. None is refused.
        assert_eq!(begin(&mut pending, 4, 4), None);
        assert_eq!(begin(&mut pending, 5, 5), None);
        for n in 6..20 {
            assert!(begin(&mut pending, n, n).is_some());
        }
        // The allowed client's dial gets room, even from the flood's own address: it gives up that
        // address's oldest stalled handshake.
        assert!(
            begin(&mut pending, 1, 30).is_some(),
            "all the room was taken"
        );
        assert!(begin(&mut pending, 1, 31).is_some());
        assert_eq!(begin(&mut pending, 1, 99), Some(30));
        // Done, it is forgotten, and the room it took is free.
        assert_eq!(begin(&mut pending, 1, 32), None);
        assert!(pending.under_way.iter().all(|&(_, n)| n != 99));
    }
}
