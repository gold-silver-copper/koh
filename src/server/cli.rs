//! The `koh serve` command: bind an endpoint with a persistent identity, admit only the clients on
//! the `--allow` list, and host each one's session. There is no "accept any peer" mode.

use std::collections::HashSet;
use std::num::NonZeroU32;
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
use crate::server::audit::{auth_event, Outcome, Throttle};
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
    /// The program each session runs, as argv, verbatim; empty for `$SHELL`.
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
    /// Most connections handled at once.
    pub max_connections: NonZeroU32,
    /// Most live sessions, one per peer.
    pub max_sessions: NonZeroU32,
    /// The binary each session's program starts through: by default the running one, which hands
    /// `__launch` to [`crate::pty::launched`].
    pub launcher: crate::pty::Launcher,
}

/// The CLI's default for `--scrollback`.
pub const DEFAULT_SCROLLBACK: u64 = 1000;
/// The CLI's default for `--session-ttl-secs`: a day, to close the laptop and reopen it later.
pub const DEFAULT_SESSION_TTL_SECS: u64 = 86_400;
/// The CLI's default for `--max-connections`.
pub const DEFAULT_MAX_CONNECTIONS: NonZeroU32 = NonZeroU32::MIN.saturating_add(63);
/// The CLI's default for `--max-sessions`.
pub const DEFAULT_MAX_SESSIONS: NonZeroU32 = NonZeroU32::MIN.saturating_add(63);
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

/// How soon a client removed from the saved clients, or added to them, is seen: one removed is
/// cut off, its session ended, within this.
pub const REVOKE_CHECK: Duration = Duration::from_secs(2);

/// How long after a read that drops a client the list is read again, to confirm it.
const CONFIRM: Duration = Duration::from_millis(500);

/// Who may connect: the ids given for this run, and the clients saved beside the server key.
pub struct Allowlist {
    given: HashSet<EndpointId>,
    /// The key the saved list sits beside, its directory judged once, and the list's path for
    /// messages.
    saved: Option<(KeyFile, String)>,
}

/// Who may connect now, as [`watch_allowlist`] publishes it.
type Allowed = watch::Receiver<Arc<HashSet<EndpointId>>>;

/// Return once `peer` is no longer allowed. Never if the list stops being published: the server is
/// then shutting down, which ends the connection anyway.
async fn revoked(mut allowed: Allowed, peer: EndpointId) {
    if allowed.wait_for(|now| !now.contains(&peer)).await.is_err() {
        std::future::pending::<()>().await;
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

/// The clients allowed, as reads of the list settle it. A read that fails (a typo) keeps the list
/// as it was. One that drops a client is taken only once the next read, [`CONFIRM`] later, agrees:
/// an editor saving the list leaves it missing or empty for a moment, which must lock no one out.
struct Settled {
    allowed: Arc<HashSet<EndpointId>>,
    /// A read that dropped a client, waiting for the next to agree.
    dropping: Option<HashSet<EndpointId>>,
    /// The last read failed, and said so.
    failing: bool,
}

impl Settled {
    const fn new(allowed: Arc<HashSet<EndpointId>>) -> Self {
        Self {
            allowed,
            dropping: None,
            failing: false,
        }
    }

    /// Take what a read gave: if that settles a change, the clients it drops. A failure is warned
    /// of once until a read succeeds again.
    fn update(&mut self, read: anyhow::Result<HashSet<EndpointId>>) -> Option<Vec<EndpointId>> {
        let read = match read {
            Ok(read) => read,
            Err(error) => {
                if !std::mem::replace(&mut self.failing, true) {
                    warn!(error = %format!("{error:#}"), "could not read the saved clients; keeping the list last read");
                }
                self.dropping = None;
                return None;
            }
        };
        self.failing = false;
        let drops = !self.allowed.is_subset(&read);
        if drops && self.dropping.as_ref() != Some(&read) {
            self.dropping = Some(read);
            return None;
        }
        self.dropping = None;
        let gone = self.allowed.difference(&read).copied().collect();
        (*self.allowed != read).then(|| {
            self.allowed = Arc::new(read);
            gone
        })
    }

    /// How long until the next read: [`CONFIRM`] while a drop waits for it, so a removal is seen
    /// within [`REVOKE_CHECK`] in all.
    fn next_read(&self) -> Duration {
        if self.dropping.is_some() {
            CONFIRM
        } else {
            REVOKE_CHECK.saturating_sub(CONFIRM)
        }
    }
}

/// Read `list` again and again ([`Settled::next_read`]), publishing each change on `allowed`, until
/// no one watches; and end in `registry` the session of each peer a change drops, connected or not.
/// The one reader of the list.
async fn watch_allowlist(
    list: Allowlist,
    allowed: watch::Sender<Arc<HashSet<EndpointId>>>,
    registry: Registry,
) {
    let list = Arc::new(list);
    let mut settled = Settled::new(allowed.borrow().clone());
    loop {
        tokio::select! {
            () = allowed.closed() => return,
            () = tokio::time::sleep(settled.next_read()) => {}
        }
        let reading = Arc::clone(&list);
        let read = tokio::task::spawn_blocking(move || reading.read())
            .await
            .map_err(anyhow::Error::from)
            .and_then(|read| read);
        if let Some(gone) = settled.update(read) {
            // Published first: the registry refuses an attach the list no longer allows, so none
            // can start a session after the end below.
            allowed.send_replace(Arc::clone(&settled.allowed));
            for peer in gone {
                registry.end(peer).await;
            }
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
        Ok(Self {
            allow,
            allowed,
            spec: SessionSpec {
                command: args.command.clone().into(),
                scrollback: usize::try_from(args.scrollback)
                    .context("scrollback does not fit in usize")?,
                max_sessions: usize::try_from(args.max_sessions.get())
                    .context("max_sessions does not fit in usize")?,
                ttl: Duration::from_secs(args.session_ttl_secs),
                launcher: args.launcher.clone(),
            },
            max_connections: usize::try_from(args.max_connections.get())
                .context("max_connections does not fit in usize")?,
        })
    }
}

/// Where a handshake comes from, for the cap on each: an IPv4 address, or an IPv6 /48 (one site's
/// share: a /64 a host, a site has 65k of them). None through a relay, where an address says
/// nothing; built from nothing else.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SourceKey(std::net::IpAddr);

impl SourceKey {
    fn of(addr: &iroh::endpoint::IncomingAddr) -> Option<Self> {
        let iroh::endpoint::IncomingAddr::Ip(at) = addr else {
            return None;
        };
        Some(Self(match at.ip() {
            std::net::IpAddr::V6(v6) => {
                std::net::Ipv6Addr::from(u128::from(v6) & !(u128::MAX >> 48)).into()
            }
            v4 @ std::net::IpAddr::V4(_) => v4,
        }))
    }
}

/// Most handshakes one address has under way at once; past them its oldest is given up.
const PER_SOURCE: usize = 2;

/// Most handshakes under way at once.
const MOST_PENDING: usize = 256;

/// The handshakes under way, oldest first, each with its address and its handle `H`: at most
/// [`PER_SOURCE`] from one address, that address's oldest given up for a new one, and at most `N`
/// in all, the oldest given up (one through a relay has no address, so only `N` holds it). Anyone
/// who can reach the port can start handshakes and stall them; this way a new handshake is never
/// refused, so an allowed client's dial, which finishes in a round trip, gets through a flood, even
/// one from its own address (the same host, a shared NAT). They hold no connection permit, so
/// stalled ones never keep a connection out.
struct Pending<H, const N: usize = MOST_PENDING>(Bounded<(Option<SourceKey>, H), N>);

impl<H, const N: usize> Pending<H, N> {
    /// Forget those `done`; then whether a handshake from `source` would give one up for its room.
    fn crowded(&mut self, source: Option<SourceKey>, done: impl Fn(&H) -> bool) -> bool {
        self.0.retain(|(_, handle)| !done(handle));
        self.0.is_full() || self.has_share(source)
    }

    fn has_share(&self, source: Option<SourceKey>) -> bool {
        source.is_some() && self.0.iter().filter(|(s, _)| *s == source).count() >= PER_SOURCE
    }

    /// Room for a handshake from `source`: the one given up for it, if any, its address's oldest
    /// when it has its share under way, else the oldest of all when all the room is taken.
    fn room(&mut self, source: Option<SourceKey>) -> Option<H> {
        let given_up = if self.has_share(source) {
            self.0.take_first(|(s, _)| *s == source)
        } else if self.0.is_full() {
            self.0.pop_front()
        } else {
            None
        };
        given_up.map(|(_, oldest)| oldest)
    }
}

/// What a finished handshake needs to be admitted, cloned for each.
#[derive(Clone)]
struct Gate {
    allowed: Allowed,
    registry: Registry,
    /// One permit a connection, held for its life.
    connections: Arc<tokio::sync::Semaphore>,
    /// Peers turned away (not allowed, or no room), said at most every few seconds: anyone can
    /// make a new id and dial.
    turned_away: Arc<Throttle>,
}

impl Gate {
    /// Serve `conn` on a task of its own if its peer is allowed (the handshake authenticated its
    /// id) and there is room for it; else close it saying why.
    fn admit(self, conn: iroh::endpoint::Connection) {
        let peer = conn.remote_id();
        let why = if !self.allowed.borrow().contains(&peer) {
            if self.turned_away.ready() {
                auth_event(Outcome::Rejected, &peer, "not on allowlist");
            }
            Close::NotAuthorized
        } else if let Ok(permit) = Arc::clone(&self.connections).try_acquire_owned() {
            #[expect(
                clippy::disallowed_methods,
                reason = "a task a connection, each holding a permit"
            )]
            drop(tokio::spawn(serve_connection(
                conn,
                self.allowed,
                self.registry,
                permit,
            )));
            return;
        } else {
            if self.turned_away.ready() {
                warn!(peer = %peer, "refusing connection: at max-connections capacity");
            }
            Close::AtCapacity
        };
        close(&conn, why);
    }
}

/// Serve the session of `conn`'s peer to it until it detaches, or the peer is removed from the
/// list, which ends its session too. The registry attaches no peer the list no longer allows: one
/// removed as this connection was admitted starts no session. Holds `permit` throughout.
async fn serve_connection(
    conn: iroh::endpoint::Connection,
    allowed: Allowed,
    registry: Registry,
    permit: tokio::sync::OwnedSemaphorePermit,
) {
    let _permit = permit;
    let peer = conn.remote_id();
    let (client, attach_kind) = match registry.attach(peer).await {
        Ok(attached) => attached,
        Err(refused) => {
            warn!(peer = %peer, reason = %refused, "refusing session");
            close(&conn, refused);
            return;
        }
    };
    auth_event(Outcome::Accepted, &peer, "authorized; session attached");
    match attach_kind {
        AttachKind::Created => info!(peer = %peer, "started a new session"),
        AttachKind::Reattached { detached_for } => info!(
            peer = %peer,
            detached_secs = detached_for.map(|d| d.as_secs()),
            "reattaching to this peer's existing session"
        ),
    }
    // Its first frame tells the client it was admitted.
    tokio::select! {
        () = run_attached(Authorized(conn.clone()), client) => {}
        () = revoked(allowed, peer) => {
            auth_event(Outcome::Rejected, &peer, "removed from the allowlist");
            close(&conn, Close::NotAuthorized);
        }
    }
}

/// Serve the allowed clients on `endpoint` until `shutdown` is cancelled or it closes, then close
/// it: `koh serve`'s accept loop, which tests run on their own transports.
pub async fn serve_endpoint(
    endpoint: iroh::Endpoint,
    hosting: Hosting,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    let (allowed_tx, allowed) = watch::channel(Arc::new(hosting.allowed));
    let allows = allowed.clone();
    let registry = Registry::spawn(hosting.spec, move |peer| allows.borrow().contains(peer))
        .context("starting the child reaper")?;
    #[expect(clippy::disallowed_methods, reason = "one allowlist reader a server")]
    tokio::spawn(watch_allowlist(hosting.allow, allowed_tx, registry.clone()));
    let gate = Gate {
        allowed,
        registry: registry.clone(),
        connections: Arc::new(tokio::sync::Semaphore::new(hosting.max_connections)),
        turned_away: Arc::new(Throttle::new()),
    };
    let mut pending: Pending<_> = Pending(Bounded::new());
    let flood = Throttle::new();

    loop {
        let incoming = tokio::select! {
            biased;
            () = shutdown.cancelled() => break,
            inc = endpoint.accept() => match inc {
                Some(i) => i,
                None => break, // endpoint closed
            },
        };
        // In order: room for the handshake, the handshake within its deadline, the allowlist, a
        // connection permit, then the session.
        let source = SourceKey::of(&incoming.remote_addr());
        // When room would cost a handshake under way, an address must first show it can be
        // answered (a QUIC retry, one round trip), which a spoofed one never does: only real
        // addresses crowd out others.
        let crowded = pending.crowded(source, tokio::task::AbortHandle::is_finished);
        let incoming = if crowded && source.is_some() && !incoming.remote_addr_validated() {
            match incoming.retry() {
                Ok(()) => continue,
                Err(validated) => validated.into_incoming(),
            }
        } else {
            incoming
        };
        let given_up = pending.room(source);
        if given_up.is_some() && flood.ready() {
            warn!("too many handshakes in flight: giving up the oldest for new ones");
        }
        given_up.iter().for_each(tokio::task::AbortHandle::abort);
        let gate = gate.clone();
        #[expect(
            clippy::disallowed_methods,
            reason = "a handshake under way, at most `MOST_PENDING`"
        )]
        let handshake = tokio::spawn(async move {
            match tokio::time::timeout(ACCEPT_HANDSHAKE_TIMEOUT, incoming).await {
                Ok(Ok(conn)) => gate.admit(conn),
                // Anyone can start one: said quietly, as a flood would say it often.
                Ok(Err(e)) => debug!(error = %Peer(e), "incoming handshake failed"),
                Err(_) => debug!("incoming handshake timed out (a stalled QUIC handshake)"),
            }
        });
        pending.0.push_evicting((source, handshake.abort_handle()));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_removal_two_reads_agree_on_drops_a_saved_client() {
        let dir = crate::test_runtime::scratch("settled");
        let places = crate::names::Places::new(None, Some(dir.join("server.key"))).unwrap();
        let id = || {
            crate::transport_iroh::generate_secret_key()
                .unwrap()
                .public()
        };
        let (laptop, phone) = (id(), id());
        let clients = dir.join("clients");
        let both = format!("laptop {laptop}\nphone {phone}\n");
        std::fs::write(&clients, &both).unwrap();
        let hosting = Hosting::from_config(&ServeConfig {
            saved_clients: Some(places),
            ..ServeConfig::default()
        })
        .unwrap();
        let mut settled = Settled::new(Arc::new(hosting.allowed));
        let mut read = |text: Option<&str>| {
            match text {
                Some(text) => std::fs::write(&clients, text).unwrap(),
                None => std::fs::remove_file(&clients).unwrap(),
            }
            settled.update(hosting.allow.read())
        };
        // An editor saving it: a typo, then emptied or gone a moment, then whole. No one is cut off.
        let typo = format!("laptop {laptop} oops\n");
        for saving in [
            [Some(&*typo), Some(&*both)],
            [Some(""), Some(&*both)],
            [None, Some(&*both)],
        ] {
            for text in saving {
                assert_eq!(read(text), None, "{text:?}");
            }
        }
        // Removed for real: the next read agrees, and only then is it dropped.
        let one = format!("laptop {laptop}\n");
        assert_eq!(read(Some(&one)), None);
        assert_eq!(read(Some(&one)), Some(vec![phone]));
        // One added is let in at once.
        assert_eq!(read(Some(&both)), Some(vec![]));
        assert!(settled.allowed.contains(&phone));
    }

    #[test]
    fn a_handshake_flood_cannot_take_an_allowed_clients_room() {
        type Handshakes = Pending<u8, 4>;
        /// A handshake from `from`'s address, numbered `n`: the one given up for it, if any.
        /// Handshake 99, the allowed client's, finishes as soon as it is under way.
        fn begin(pending: &mut Handshakes, from: u8, n: u8) -> Option<u8> {
            let source = Some(SourceKey(std::net::IpAddr::from([203, 0, 113, from])));
            let crowded = pending.crowded(source, |&h| h == 99);
            let given_up = pending.room(source);
            assert_eq!(crowded, given_up.is_some(), "{n}");
            pending.0.push_evicting((source, n));
            given_up
        }
        let mut pending = Pending(Bounded::new());
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
        assert!(pending.0.iter().all(|&(_, n)| n != 99));
    }
}
