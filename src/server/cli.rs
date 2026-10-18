//! The `koh serve` command: admit only the clients on the allowlist, and serve each what it asks.
//!
//! It binds an endpoint with a persistent identity, and serves each connection what its opening
//! request asks: a session, the peer's sessions, a command or a copy. There is no "accept any
//! peer" mode.

use std::collections::HashMap;
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
use crate::names::{List, Scope};
use crate::proto::Close;
use crate::request::{
    Answer, Attached, On, Pick, Problem, ProblemKind, Request, Resume, SessionList, Until,
    MAX_LISTED, MAX_OUTPUT, MAX_REQUEST,
};
use crate::server::audit::{auth_event, Outcome, Throttle};
use crate::server::place::Place;
use crate::server::session::{AttachKind, Registry, SessionSpec};
use crate::transport_iroh::{bind_on, close, Network, PROTOCOL};
use tracing::{debug, info, warn};

/// Deadline on the QUIC handshake, so a stalled dial gives up its place among those pending rather
/// than keep it for the 5-minute idle timeout; a real handshake takes far less, even on a slow
/// mobile link.
const ACCEPT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Deadline on the opening request, as on the handshake: a peer that says nothing is closed, and
/// holds its permit no longer.
const REQUEST_TIMEOUT: Duration = ACCEPT_HANDSHAKE_TIMEOUT;

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
    /// Bytes of scrollback each session's emulator keeps, at most [`MAX_SCROLLBACK_BYTES`].
    pub scrollback_bytes: u64,
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
    /// Most live sessions, all peers' together.
    pub max_sessions: NonZeroU32,
    /// The home each session's program gets: the user's, but in tests.
    pub home: crate::pty::Home,
    /// Start a session's bash, zsh or fish so that it marks its commands (OSC 133).
    pub shell_marks: bool,
    /// Bytes of output each job keeps, at most [`MAX_JOB_LOG_BYTES`].
    pub job_log_bytes: u64,
}

/// The CLI's default for `--scrollback-bytes`: 8 MiB, as fux keeps.
pub const DEFAULT_SCROLLBACK_BYTES: u64 = 8 << 20;
/// The CLI's default for `--session-ttl-secs`: a day, to close the laptop and reopen it later.
pub const DEFAULT_SESSION_TTL_SECS: u64 = 86_400;
/// The CLI's default for `--max-connections`.
pub const DEFAULT_MAX_CONNECTIONS: NonZeroU32 = NonZeroU32::MIN.saturating_add(63);
/// The CLI's default for `--max-sessions`.
pub const DEFAULT_MAX_SESSIONS: NonZeroU32 = NonZeroU32::MIN.saturating_add(63);
/// Upper bound on `scrollback_bytes`, 1 GiB: past what fux-vt's history holds whatever its budget
/// (64 Mi cells at 8 bytes, and their text).
pub const MAX_SCROLLBACK_BYTES: u64 = 1 << 30;
/// The CLI's default for `--job-log-bytes`: 4 MiB.
pub const DEFAULT_JOB_LOG_BYTES: u64 = 4 << 20;
/// Upper bound on `job_log_bytes`: each of [`super::jobs::MAX_JOBS`] jobs may hold twice it.
pub const MAX_JOB_LOG_BYTES: u64 = 64 << 20;

impl Default for ServeConfig {
    fn default() -> Self {
        Self {
            key_file: None,
            allow: Vec::new(),
            saved_clients: None,
            command: Vec::new(),
            scrollback_bytes: DEFAULT_SCROLLBACK_BYTES,
            session_ttl_secs: DEFAULT_SESSION_TTL_SECS,
            relay_url: None,
            local: false,
            port: None,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            max_sessions: DEFAULT_MAX_SESSIONS,
            home: crate::pty::Home::user(),
            shell_marks: true,
            job_log_bytes: DEFAULT_JOB_LOG_BYTES,
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
    let endpoint = bind_on(
        secret,
        (true, crate::transport_iroh::Idle::Shell),
        &network,
        args.port,
    )
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

/// Who may connect, each with its scope.
type Clients = HashMap<EndpointId, Scope>;

/// Who may connect: the ids given for this run, and the clients saved beside the server key.
pub struct Allowlist {
    given: Clients,
    /// The key the saved list sits beside, its directory judged once, and the list's path for
    /// messages.
    saved: Option<(KeyFile, String)>,
}

/// Who may connect now, as [`watch_allowlist`] publishes it.
type Allowed = watch::Receiver<Arc<Clients>>;

/// Return once `peer` is no longer allowed with `scope`: removed, or its scope changed. Never if
/// the list stops being published: the server is then shutting down, which ends the connection
/// anyway.
async fn revoked(mut allowed: Allowed, peer: EndpointId, scope: Scope) {
    if allowed
        .wait_for(|now| now.get(&peer) != Some(&scope))
        .await
        .is_err()
    {
        std::future::pending::<()>().await;
    }
}

impl Allowlist {
    /// The clients who may connect as the saved list says now, and their scopes: one given for
    /// this run may do everything.
    fn read(&self) -> anyhow::Result<Clients> {
        let mut allowed = Clients::new();
        if let Some((key, shown)) = &self.saved {
            let saved = crate::names::read(key, List::Clients, shown)?;
            allowed.extend(saved.entries().map(|entry| (entry.id, entry.scope.clone())));
        }
        allowed.extend(self.given.iter().map(|(id, scope)| (*id, scope.clone())));
        Ok(allowed)
    }
}

/// What reads of the list have settled. A read that fails (a typo) keeps the list as it was. One
/// that drops a client is taken only once the next read, [`CONFIRM`] later, agrees: an editor
/// saving the list leaves it missing or empty for a moment, which must lock no one out.
#[derive(Default)]
struct Settling {
    /// A read that dropped a client, waiting for the next to agree.
    dropping: Option<Clients>,
    /// The last read failed, and said so.
    failing: bool,
}

impl Settling {
    /// What the list allowing `now` is to become after `read`, if it changes. A failure is warned
    /// of once until a read succeeds again.
    fn settle(&mut self, now: &Clients, read: anyhow::Result<Clients>) -> Option<Clients> {
        if let Some(error) = read.as_ref().err().filter(|_| !self.failing) {
            warn!(error = %format!("{error:#}"), "could not read the saved clients; keeping the list last read");
        }
        self.failing = read.is_err();
        let (read, dropping) = (read.ok()?, self.dropping.take());
        // A client removed, or its scope changed: what it may do is less, or other.
        let drops = now.iter().any(|(id, scope)| read.get(id) != Some(scope));
        if drops && dropping.as_ref() != Some(&read) {
            self.dropping = Some(read);
            return None;
        }
        (*now != read).then_some(read)
    }
}

/// Read `list` again and again, publishing each change on `allowed`, until no one watches; and end
/// in `registry` the session of each peer a change drops, connected or not. The one reader of the
/// list: every [`REVOKE_CHECK`], [`CONFIRM`] included, so a removal is seen within it.
async fn watch_allowlist(
    list: Allowlist,
    allowed: watch::Sender<Arc<Clients>>,
    registry: Registry,
) {
    let list = Arc::new(list);
    let mut settling = Settling::default();
    loop {
        let wait = if settling.dropping.is_some() {
            CONFIRM
        } else {
            REVOKE_CHECK.saturating_sub(CONFIRM)
        };
        tokio::select! {
            () = allowed.closed() => return,
            () = tokio::time::sleep(wait) => {}
        }
        let reading = Arc::clone(&list);
        let read = tokio::task::spawn_blocking(move || reading.read())
            .await
            .map_err(anyhow::Error::from)
            .and_then(|read| read);
        let now = allowed.borrow().clone();
        if let Some(next) = settling.settle(&now, read) {
            // Removed, or scoped where it was not: its sessions end.
            let gone: Vec<EndpointId> = now
                .keys()
                .filter(|id| next.get(*id).is_none_or(|scope| !scope.is_full()))
                .copied()
                .collect();
            // Published first: the registry refuses an attach the list no longer allows, so none
            // can start a session after the end below.
            allowed.send_replace(Arc::new(next));
            for peer in gone {
                registry.end(peer).await;
            }
        }
    }
}

/// A validated [`ServeConfig`]: who may connect, what each session runs, and the limits.
pub struct Hosting {
    allow: Allowlist,
    /// Who may connect, as first read.
    allowed: Clients,
    spec: SessionSpec,
    max_connections: usize,
    job_log_bytes: usize,
}

impl Hosting {
    /// Validate `args`: clap checks these ranges, but a `ServeConfig` built in code does not.
    pub fn from_config(args: &ServeConfig) -> anyhow::Result<Self> {
        anyhow::ensure!(
            args.scrollback_bytes <= MAX_SCROLLBACK_BYTES,
            "scrollback of {} bytes exceeds the maximum of {MAX_SCROLLBACK_BYTES}",
            args.scrollback_bytes
        );
        let saved = args
            .saved_clients
            .as_ref()
            .map(|places| {
                let key = KeyFile::open(places.key(List::Clients.role()))?;
                anyhow::Ok((key, crate::names::shown(places, List::Clients)))
            })
            .transpose()?;
        anyhow::ensure!(
            args.job_log_bytes <= MAX_JOB_LOG_BYTES,
            "a job log of {} bytes exceeds the maximum of {MAX_JOB_LOG_BYTES}",
            args.job_log_bytes
        );
        let allow = Allowlist {
            given: args
                .allow
                .iter()
                .map(|id| (*id, Scope::default()))
                .collect(),
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
                scrollback_bytes: usize::try_from(args.scrollback_bytes)
                    .context("scrollback does not fit in usize")?,
                max_sessions: usize::try_from(args.max_sessions.get())
                    .context("max_sessions does not fit in usize")?,
                ttl: Duration::from_secs(args.session_ttl_secs),
                home: args.home.clone(),
                marks: args
                    .shell_marks
                    .then(|| super::marks::MarksDir::new(&args.home.runtime_dir()).map(Arc::new))
                    .transpose()
                    .context("naming the directory for the shells' startup files")?,
            },
            max_connections: usize::try_from(args.max_connections.get())
                .context("max_connections does not fit in usize")?,
            job_log_bytes: usize::try_from(args.job_log_bytes)
                .context("job_log_bytes does not fit in usize")?,
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

/// What a connection's request may use beside the sessions: where commands run and copies
/// land, what reaps commands hung up, and the server's shutdown, which hangs them up.
pub(super) struct Host {
    pub(super) home: crate::pty::Home,
    pub(super) reaper: crate::pty::Reaper,
    pub(super) shutdown: CancellationToken,
    pub(super) jobs: super::jobs::Jobs,
}

/// What a finished handshake needs to be admitted, cloned for each.
#[derive(Clone)]
struct Gate {
    allowed: Allowed,
    registry: Registry,
    host: Arc<Host>,
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
        let scope = self.allowed.borrow().get(&peer).cloned();
        let why = if let Some(scope) = scope {
            if let Ok(permit) = Arc::clone(&self.connections).try_acquire_owned() {
                #[expect(
                    clippy::disallowed_methods,
                    reason = "a task a connection, each holding a permit"
                )]
                drop(tokio::spawn(serve_connection(
                    conn,
                    (self.allowed, scope),
                    self.registry,
                    self.host,
                    permit,
                )));
                return;
            }
            if self.turned_away.ready() {
                warn!(peer = %peer, "refusing connection: at max-connections capacity");
            }
            Close::AtCapacity
        } else {
            if self.turned_away.ready() {
                auth_event(Outcome::Rejected, &peer, "not on allowlist");
            }
            Close::NotAuthorized
        };
        close(&conn, why);
    }
}

/// Serve what `conn`'s opening request asks until it is done, or the peer is removed from the
/// list, which ends its sessions too. The registry attaches no peer the list no longer allows: one
/// removed as this connection was admitted starts no session. Holds `permit` throughout, the wait
/// for the request included.
async fn serve_connection(
    conn: iroh::endpoint::Connection,
    (allowed, scope): (Allowed, Scope),
    registry: Registry,
    host: Arc<Host>,
    permit: tokio::sync::OwnedSemaphorePermit,
) {
    let _permit = permit;
    let peer = conn.remote_id();
    let served = async {
        let Some((request, control)) = opening(&conn).await else {
            return;
        };
        let Some(place) = permitted(&request, &scope, &host) else {
            auth_event(Outcome::Rejected, &peer, "out of its scope");
            info!(peer = %peer, asked = request.what(), "a scoped key asked for more than its scope");
            close(&conn, Close::OutOfScope);
            return;
        };
        auth_event(Outcome::Accepted, &peer, request.what());
        dispatch(&conn, request, control, (&registry, &host, &place)).await;
    };
    tokio::select! {
        () = served => {}
        () = revoked(allowed, peer, scope.clone()) => {
            auth_event(Outcome::Rejected, &peer, "removed from the allowlist, or its scope changed");
            close(&conn, Close::NotAuthorized);
        }
    }
}

/// Where `request`'s paths are for a key of `scope`, if the scope allows it at all: a full key's
/// in the server user's home; a scoped one's in the directory its scope names for what it asks.
fn permitted(request: &Request, scope: &Scope, host: &Host) -> Option<Place> {
    let home = host.home.dir();
    if scope.is_full() {
        return Some(Place::new(home, None));
    }
    let root = match request {
        Request::Exec(_)
        | Request::Start { .. }
        | Request::Jobs
        | Request::Logs { .. }
        | Request::Kill { .. } => scope.exec.clone(),
        Request::Wait(wait) => match (&wait.on, &wait.until) {
            (Some(On::Job(_)), _) => scope.exec.clone(),
            (None, Until::File(_)) => scope.exec.clone().or_else(|| scope.cp.clone()),
            (Some(On::Session(_)) | None, _) => None,
        },
        Request::Copy(_) => scope.cp.clone(),
        Request::Shell { .. } | Request::Sessions | Request::Output { .. } => None,
    };
    root.map(|root| Place::new(home, Some(root)))
}

/// Serve `request` for `conn`'s client at `place`; `control` is the rest of its first stream.
async fn dispatch(
    conn: &iroh::endpoint::Connection,
    request: Request,
    control: iroh::endpoint::RecvStream,
    (registry, host, place): (&Registry, &Host, &Place),
) {
    let peer = conn.remote_id();
    match request {
        Request::Shell { pick, size } => shell(conn, registry, (pick, size), control).await,
        Request::Sessions => {
            let mut sessions = registry.sessions(peer).await;
            sessions.truncate(MAX_LISTED);
            super::answer(conn, &Answer::Ok(SessionList(sessions))).await;
        }
        Request::Output { session, last } => {
            let text: Answer<String> = match registry.find(peer, session).await {
                Some(found) => found.text(last).await.ok_or_else(|| {
                    Problem::new(
                        ProblemKind::NotFound,
                        "no command finished whose output is still kept",
                    )
                }),
                None => Err(Problem::new(ProblemKind::NoSuchSession, session)),
            };
            if super::reply_at_most(conn, &text, MAX_OUTPUT).await.is_ok() {
                super::linger(conn).await;
            }
        }
        Request::Exec(run) => super::exec::serve(conn, control, &run, host, place).await,
        Request::Start { name, run } => {
            let started = host.jobs.start(peer, name, &run, host, place);
            if let Ok(started) = &started {
                info!(peer = %peer, job = %started.name, "started a job");
            }
            super::answer(conn, &started).await;
        }
        Request::Jobs => {
            let mut jobs = host.jobs.list(peer);
            jobs.0.truncate(MAX_LISTED);
            super::answer(conn, &Answer::Ok(jobs)).await;
        }
        Request::Logs { job, follow } => {
            if let Some(found) = host.jobs.get(peer, &job) {
                super::jobs::logs(conn, &found, follow).await;
            } else {
                let none: Answer<()> = Err(Problem::new(ProblemKind::NoSuchJob, &job));
                super::answer(conn, &none).await;
            }
        }
        Request::Kill { job, signal } => {
            super::answer(conn, &host.jobs.kill(peer, &job, signal)).await;
        }
        Request::Wait(wait) => {
            super::wait::serve(conn, peer, &wait, (registry, &host.jobs), place).await;
        }
        Request::Copy(copy) => super::copy::serve(conn, control, copy, place).await,
    }
}

/// The request `conn`'s client opens with, and the rest of its stream, read within
/// [`REQUEST_TIMEOUT`]: else the connection is closed, as one that broke the protocol.
async fn opening(
    conn: &iroh::endpoint::Connection,
) -> Option<(Request, iroh::endpoint::RecvStream)> {
    let read = async {
        let mut control = conn.accept_uni().await?;
        let body = crate::transport_iroh::read_framed(&mut control, MAX_REQUEST).await?;
        let request: Request = crate::request::decode(&body)?;
        anyhow::Ok((request, control))
    };
    match tokio::time::timeout(REQUEST_TIMEOUT, read).await {
        Ok(Ok(opened)) => Some(opened),
        Ok(Err(error)) => {
            debug!(error = %Peer(format!("{error:#}")), "no opening request");
            close(conn, Close::ProtocolError);
            None
        }
        Err(_) => {
            debug!("no opening request in time");
            close(conn, Close::ProtocolError);
            None
        }
    }
}

/// Attach `conn`'s peer to the session `pick` names and serve it until it detaches; the rest of
/// the client's first stream, `control`, is the session's control stream.
async fn shell(
    conn: &iroh::endpoint::Connection,
    registry: &Registry,
    (pick, size): (Pick, crate::terminal::Size),
    control: iroh::endpoint::RecvStream,
) {
    let peer = conn.remote_id();
    let (client, start, attach_kind) = match registry.attach(peer, pick, size).await {
        Ok(attached) => attached,
        Err(refused) => {
            warn!(peer = %peer, reason = %refused, "refusing session");
            close(conn, refused);
            return;
        }
    };
    let session = client.session();
    match attach_kind {
        AttachKind::Created => info!(peer = %peer, %session, "started a new session"),
        AttachKind::Reattached { detached_for } => info!(
            peer = %peer,
            %session,
            detached_secs = detached_for.map(|d| d.as_secs()),
            "reattaching to this peer's session"
        ),
    }
    // Its first stream tells the client it was admitted, and to which session. The session is
    // the proof the peer is allowed: the registry attaches no other.
    let attached = Attached {
        at: Resume {
            run: registry.run(),
            session,
        },
    };
    if super::reply(conn, &attached).await.is_ok() {
        super::attach::serve(conn, client, start, control).await;
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
    let home = hosting.spec.home.clone();
    // Only a key that may do everything gets a session.
    let ttl = hosting.spec.ttl;
    let registry = Registry::spawn(hosting.spec, move |peer| {
        allows.borrow().get(peer).is_some_and(Scope::is_full)
    })
    .context("starting the child reaper")?;
    let host = Arc::new(Host {
        home,
        reaper: registry.reaper(),
        shutdown: shutdown.clone(),
        jobs: super::jobs::Jobs::new(hosting.job_log_bytes, ttl),
    });
    #[expect(clippy::disallowed_methods, reason = "one allowlist reader a server")]
    tokio::spawn(watch_allowlist(hosting.allow, allowed_tx, registry.clone()));
    let gate = Gate {
        allowed,
        registry: registry.clone(),
        host: Arc::clone(&host),
        connections: Arc::new(tokio::sync::Semaphore::new(hosting.max_connections)),
        turned_away: Arc::default(),
    };
    let mut pending: Pending<_> = Pending(Bounded::new());
    let flood = Throttle::default();

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

    // Sessions first, with their programs reaped (or killed after their grace), then the endpoint;
    // the commands hung up as the shutdown reached them are reaped last.
    info!("draining: stopping the registry and closing endpoint");
    shutdown.cancel();
    registry.shutdown().await;
    if !crate::transport_iroh::close_endpoint(&endpoint).await {
        warn!("peers did not see the endpoint close in time; exiting anyway");
    }
    let reaper = host.reaper.clone();
    let _ = tokio::task::spawn_blocking(move || reaper.drain()).await;
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
        let (mut allowed, mut settling) = (hosting.allowed, Settling::default());
        // The list as `text`, or gone: the clients it drops once that is settled, if it changes.
        let mut read = |text: Option<&str>| {
            match text {
                Some(text) => std::fs::write(&clients, text).unwrap(),
                None => std::fs::remove_file(&clients).unwrap(),
            }
            let next = settling.settle(&allowed, hosting.allow.read())?;
            let gone: Vec<_> = allowed
                .keys()
                .filter(|id| !next.contains_key(*id))
                .copied()
                .collect();
            allowed = next;
            Some(gone)
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
