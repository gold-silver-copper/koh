//! The client's commands that dial a server: `koh connect`, which runs
//! [`crate::client::run_client`] on the real terminal, `koh sessions`, and the dialing `koh exec`
//! and `koh cp` share.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::Context;
use iroh::endpoint::{Connection, SendStream};
use iroh::{EndpointId, RelayUrl};
use tokio_util::sync::CancellationToken;

pub use crate::client::copy::{copy, CopyJob};
pub use crate::client::exec::exec;
use crate::client::{
    refusal, Admitted, BackendTerminal, ClientTerminal as _, DefaultBackend, IrohConnector,
};
use crate::request::{Pick, Presence, Request, SessionInfo, SessionList, MAX_REPLY};
use crate::transport_iroh::{bind_on, close_endpoint, Network};

/// How long the first dial may take.
const DIAL_TIMEOUT: Duration = Duration::from_secs(15);

/// The server a command dials, and how.
#[derive(Debug, Clone)]
pub struct Remote {
    /// Server endpoint id to connect to.
    pub server: EndpointId,
    /// The secret-key file; `None` for the default client key path.
    pub key_file: Option<PathBuf>,
    /// Dial this socket address directly, with no relay or discovery; wins over `relay_url`.
    pub direct: Option<SocketAddr>,
    /// Dial through a self-hosted relay instead of n0's.
    pub relay_url: Option<RelayUrl>,
}

impl Remote {
    /// `server`, dialed through n0's relays and discovery, as the default client key.
    pub const fn new(server: EndpointId) -> Self {
        Self {
            server,
            key_file: None,
            direct: None,
            relay_url: None,
        }
    }
}

/// The clap-free form of `koh connect`'s arguments.
#[derive(Debug, Clone)]
pub struct ConnectConfig {
    pub remote: Remote,
    /// Which of this client's sessions to attach to.
    pub pick: Pick,
    /// Let the server set the clipboard (OSC 52); on unless `--no-clipboard`.
    pub clipboard: bool,
    /// Paint the server's hyperlinks (OSC 8); on unless `--no-hyperlinks`.
    pub hyperlinks: bool,
    /// Ask the user's terminal its colours and tell the server, which answers programs' colour
    /// queries with them; on unless `--no-colours`.
    pub colours: bool,
    /// A shell command to run on the remote bell (see [`BellHook`]).
    pub bell_command: Option<String>,
}

impl ConnectConfig {
    /// A config for dialing `server` with every other option at the CLI default.
    pub const fn new(server: EndpointId) -> Self {
        Self {
            remote: Remote::new(server),
            pick: Pick::Latest,
            clipboard: true,
            hyperlinks: true,
            colours: true,
            bell_command: None,
        }
    }
}

/// Runs a command (`sh -c`) when the remote bell rings (`--on-bell`), at most once a second.
///
/// The command is detached, with its stdio on `/dev/null` (the TUI owns the terminal),
/// `KOH_BELL_COUNT` and `KOH_TITLE` set and every other `KOH_*` variable scrubbed. The bell count
/// is cumulative for the server session, so the first synced frame [`prime`](Self::prime)s it:
/// bells from before the attach do not fire, bells during a reconnect do.
#[derive(Debug, Clone)]
pub struct BellHook {
    command: String,
    /// The last count seen (by `prime` or `observe`), after which `prime` is a no-op.
    last_count: Option<u64>,
    last_spawn: Option<Instant>,
}

/// Minimum spacing between two hook spawns; a burst of bells inside it coalesces into one.
pub const BELL_HOOK_MIN_INTERVAL: Duration = Duration::from_secs(1);

impl BellHook {
    pub fn new(command: impl Into<String>) -> Self {
        Self {
            command: command.into(),
            last_count: None,
            last_spawn: None,
        }
    }

    /// Take `count` as seen, without firing, unless a count was seen already.
    pub fn prime(&mut self, count: u64) {
        self.last_count.get_or_insert(count);
    }

    /// Note the bell count at `now`; whether to fire: it rose, and the last spawn was at least
    /// [`BELL_HOOK_MIN_INTERVAL`] ago. A rise within that is absorbed, not deferred.
    pub fn observe(&mut self, count: u64, now: Instant) -> bool {
        let rose = count > self.last_count.replace(count).unwrap_or(0);
        let spaced = rose
            && self
                .last_spawn
                .is_none_or(|at| now.saturating_duration_since(at) >= BELL_HOOK_MIN_INTERVAL);
        if spaced {
            self.last_spawn = Some(now);
        }
        spaced
    }

    /// The command to spawn, with `parent_env` scrubbed of `KOH_*` (given, so tests can pass their
    /// own).
    pub(crate) fn command(
        &self,
        count: u64,
        title: &str,
        parent_env: impl IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
    ) -> std::process::Command {
        #[expect(
            clippy::disallowed_methods,
            reason = "the user's own --on-bell command"
        )]
        let mut cmd = std::process::Command::new("sh");
        cmd.arg("-c").arg(&self.command).env_clear();
        for (k, v) in parent_env {
            if !crate::pty::is_koh_env_key(&k) {
                cmd.env(k, v);
            }
        }
        cmd.env("KOH_BELL_COUNT", count.to_string())
            .env("KOH_TITLE", title)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        cmd
    }

    /// Spawn the command, reaped on a thread of its own so it can never block the session.
    pub fn fire(&self, count: u64, title: &str) {
        match self.command(count, title, std::env::vars_os()).spawn() {
            Ok(mut child) => {
                let reaper = std::thread::Builder::new()
                    .name("koh-bell-hook".into())
                    .spawn(move || {
                        let _ = child.wait();
                    });
                if let Err(e) = reaper {
                    tracing::warn!(error = %e, "bell hook reaper thread spawn failed");
                }
            }
            Err(e) => tracing::warn!(error = %e, "bell hook spawn failed"),
        }
    }
}

/// Bind an endpoint to dial `remote` from, as `identity`, and the connector that dials it.
async fn connector(
    remote: &Remote,
    identity: &crate::identity::Identity,
) -> anyhow::Result<(iroh::Endpoint, IrohConnector)> {
    let secret = identity.secret.clone();
    let server = remote.server;
    let (network, target) = match (remote.direct, remote.relay_url.clone()) {
        (Some(addr), _) => (
            Network::Local,
            iroh::EndpointAddr::new(server).with_ip_addr(addr),
        ),
        (None, Some(relay)) => (
            Network::Relay(relay.clone()),
            iroh::EndpointAddr::new(server).with_relay_url(relay),
        ),
        (None, None) => (Network::N0, server.into()),
    };
    let endpoint = bind_on(secret, false, &network, None).await?;
    let connector = IrohConnector::new(endpoint.clone(), target);
    Ok((endpoint, connector))
}

/// `future`, the first dial, within [`DIAL_TIMEOUT`]; failing, `endpoint` is closed.
async fn first_dial<T>(
    endpoint: &iroh::Endpoint,
    future: impl std::future::Future<Output = anyhow::Result<T>>,
) -> anyhow::Result<T> {
    let first = tokio::time::timeout(DIAL_TIMEOUT, future)
        .await
        .context("timed out connecting (server unreachable or not responding)")
        .and_then(std::convert::identity);
    if first.is_err() {
        let _ = close_endpoint(endpoint).await;
    }
    first
}

/// Bind an endpoint for `config` and make the first connection; the connector redials the same
/// target.
async fn dial(
    config: &ConnectConfig,
    identity: &crate::identity::Identity,
) -> anyhow::Result<(iroh::Endpoint, IrohConnector, Admitted)> {
    let (endpoint, connector) = connector(&config.remote, identity).await?;
    let admitted = first_dial(&endpoint, connector.connect(config.pick)).await?;
    Ok((endpoint, connector, admitted))
}

/// One connection to a server for one request: `koh exec`'s, `koh cp`'s or `koh sessions`'.
pub(crate) struct Opened {
    pub(crate) conn: Connection,
    /// The client's first stream, the request on it, open for what follows.
    pub(crate) control: SendStream,
    endpoint: iroh::Endpoint,
    /// Held while connected: its lease stops `koh key reset`.
    _identity: crate::identity::Identity,
}

impl Opened {
    /// Dial `remote` as its client key and make `request`.
    pub(crate) async fn dial(remote: &Remote, request: &Request) -> anyhow::Result<Self> {
        log_to_koh_log();
        let identity = crate::identity::load(&crate::identity::KeyFile::locate(
            remote.key_file.clone(),
            "client",
        )?)?;
        let (endpoint, connector) = connector(remote, &identity).await?;
        let (conn, control) = first_dial(&endpoint, connector.open(request)).await?;
        Ok(Self {
            conn,
            control,
            endpoint,
            _identity: identity,
        })
    }

    /// Done: close the connection, telling the server at once.
    pub(crate) async fn close(self) {
        self.conn.close(0u32.into(), b"done");
        let _ = close_endpoint(&self.endpoint).await;
    }
}

/// `koh sessions`: this client's sessions on `remote`, one a line, to `out`.
pub async fn sessions(remote: &Remote, out: &mut impl std::io::Write) -> anyhow::Result<()> {
    let mut opened = Opened::dial(remote, &Request::Sessions).await?;
    opened.control.finish()?;
    let listed = async {
        let mut recv = opened.conn.accept_uni().await?;
        let bytes = recv.read_to_end(MAX_REPLY.saturating_add(4)).await?;
        anyhow::Ok(crate::request::decode_framed::<SessionList>(
            &bytes, MAX_REPLY,
        )?)
    };
    let listed = listed.await.map_err(|e| refusal(&opened.conn, &e));
    opened.close().await;
    for info in listed?.0 {
        writeln!(out, "{}", listing(&info))?;
    }
    Ok(())
}

/// One session as `koh sessions` lists it: space-separated fields, none holding a space, then the
/// title, escaped, to the line's end: `3 detached=5m age=2h01m 80x24 running vim notes`.
fn listing(info: &SessionInfo) -> String {
    let presence = match info.presence {
        Presence::Attached => "attached".to_owned(),
        Presence::Detached { secs } => format!("detached={}", span(secs)),
    };
    let program = info
        .exited
        .map_or_else(|| "running".to_owned(), |code| format!("exited={code}"));
    // A program chose it: nothing in it may move the cursor or reorder the line.
    let mut title = String::with_capacity(info.title.len());
    for c in info.title.chars() {
        if c == ' ' || !(c.is_control() || c.is_whitespace() || crate::log::is_bidi(c)) {
            title.push(c);
        } else {
            title.extend(c.escape_default());
        }
    }
    format!(
        "{} {presence} age={} {}x{} {program} {title}",
        info.session,
        span(info.age_secs),
        info.size.cols,
        info.size.rows,
    )
    .trim_end()
    .to_owned()
}

/// `secs` in its two largest units: `45s`, `3m12s`, `2h05m`, `4d03h`.
fn span(secs: u64) -> String {
    let (m, h, d) = (
        secs.div_euclid(60),
        secs.div_euclid(3600),
        secs.div_euclid(86_400),
    );
    if d > 0 {
        format!("{d}d{:02}h", h.rem_euclid(24))
    } else if h > 0 {
        format!("{h}h{:02}m", m.rem_euclid(60))
    } else if m > 0 {
        format!("{m}m{:02}s", secs.rem_euclid(60))
    } else {
        format!("{secs}s")
    }
}

/// Warn if the locale does not look UTF-8, which koh assumes; mosh refuses to run instead.
fn warn_if_locale_not_utf8() {
    // In POSIX's order of precedence.
    let locale = ["LC_ALL", "LC_CTYPE", "LANG"]
        .iter()
        .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()));
    let looks_utf8 = locale.as_deref().is_some_and(|l| {
        let l = l.to_ascii_lowercase();
        l.contains("utf-8") || l.contains("utf8")
    });
    if !looks_utf8 {
        let shown = locale.as_deref().unwrap_or("(unset)");
        crate::log::stderr(format_args!(
            "koh: warning: locale {shown} does not look UTF-8; non-ASCII output may be garbled. \
             Set e.g. LANG=en_US.UTF-8."
        ));
    }
}

/// With `$KOH_LOG` set, log to that file at debug level (the TUI owns the terminal). It must be
/// a private file of this user's (see [`crate::identity::open_private_log`]), as debug logs can be
/// sensitive; failing that, nothing is logged. An empty `$KOH_LOG` is off, silently.
fn log_to_koh_log() {
    let Some(path) = std::env::var_os("KOH_LOG").filter(|path| !path.is_empty()) else {
        return;
    };
    match crate::identity::open_private_log(path.as_ref()) {
        Ok(file) => crate::log::init(std::sync::Mutex::new(file), tracing::Level::DEBUG),
        Err(e) => {
            crate::log::stderr(format_args!(
                "koh: warning: $KOH_LOG: {e}; file logging disabled"
            ));
        }
    }
}

/// `koh connect`: the remote shell's exit code if it exited. Takes the process's terminal, stdin
/// and signal handlers for the session.
pub async fn connect(args: ConnectConfig) -> anyhow::Result<Option<u32>> {
    log_to_koh_log();

    warn_if_locale_not_utf8();

    // Before dialing, so a run with no terminal (a script's, an agent's) starts nothing there.
    let backend = DefaultBackend::new().map_err(|error| {
        anyhow::anyhow!(
            "`koh connect` needs a terminal, and there is none here ({error}); \
             `koh exec SERVER -- COMMAND` runs a command without one, and `koh cp` copies files"
        )
    })?;
    // Held for the session: its lease stops `koh key reset` while it may redial.
    let identity = crate::identity::load(&crate::identity::KeyFile::locate(
        args.remote.key_file.clone(),
        "client",
    )?)?;
    let (endpoint, connector, channel) = dial(&args, &identity).await?;
    // For the menu's "last connected"; failing to note it never stops the session.
    let noted = crate::identity::KeyFile::path_for(args.remote.key_file.clone(), "client")
        .map_err(anyhow::Error::from)
        .and_then(|key| crate::names::record_connected(&key, args.remote.server));
    if let Err(error) = noted {
        tracing::debug!(error = %format!("{error:#}"), "noting when the server was reached");
    }
    let dialed_at = std::time::SystemTime::now();
    let shutdown = CancellationToken::new();
    // Armed before raw mode is entered, so an install error surfaces while the terminal is cooked.
    crate::cancel_on_signals(&shutdown).context("installing the signal handlers")?;
    let (channels, tasks) = super::spawn_client_io()?;
    let result = async {
        let mut terminal = BackendTerminal::enter(backend, args.clipboard)
            .context("entering raw mode / alt screen")?;
        terminal.set_hyperlinks(args.hyperlinks);
        let size = terminal.size().unwrap_or(crate::terminal::DEFAULT_SIZE);
        crate::client::run_client(
            channel,
            dialed_at,
            connector,
            size,
            args.colours,
            channels.input_rx,
            channels.resize_rx,
            terminal,
            shutdown,
            args.bell_command.map(BellHook::new),
        )
        .await
    }
    .await;
    let _ = close_endpoint(&endpoint).await;
    drop(identity);
    super::io::first_error(result, tasks.shutdown().await)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redial_reuses_the_loaded_identity_without_touching_the_key_file() -> anyhow::Result<()> {
        crate::test_runtime::current_thread().block_on(async {
            use crate::transport_iroh::{bind_endpoint_local, generate_secret_key};
            let server = bind_endpoint_local(generate_secret_key()?, true).await?;
            let identity = crate::identity::Identity::generate()?;
            let expected = identity.secret.public();
            let socket = server
                .bound_sockets()
                .into_iter()
                .find(std::net::SocketAddr::is_ipv4)
                .context("server IPv4 socket")?;
            let config = ConnectConfig {
                remote: Remote {
                    // Any attempt to reload instead of reusing `identity` would fail here.
                    key_file: Some("/nonexistent/koh-redial-test.key".into()),
                    direct: Some(([127, 0, 0, 1], socket.port()).into()),
                    ..Remote::new(server.id())
                },
                ..ConnectConfig::new(server.id())
            };
            let peer = server.clone();
            let accept = async move {
                for _ in 0..2 {
                    let connection = peer.accept().await.context("accept connection")?.await?;
                    anyhow::ensure!(
                        connection.remote_id() == expected,
                        "client identity changed"
                    );
                    let _control = crate::client::admit(&connection).await?;
                    connection.closed().await;
                }
                Ok::<_, anyhow::Error>(())
            };
            let client = async {
                let (endpoint, connector, channel) = dial(&config, &identity).await?;
                channel.conn.close(0u32.into(), b"test reconnect");
                // The same connector `run_client` redials with after a link loss.
                let channel = connector.connect(Pick::Resume(channel.at)).await?;
                channel.conn.close(0u32.into(), b"test done");
                endpoint.close().await;
                Ok::<_, anyhow::Error>(())
            };
            tokio::time::timeout(
                Duration::from_secs(15),
                Box::pin(async { tokio::try_join!(accept, client) }),
            )
            .await??;
            server.close().await;
            Ok(())
        })
    }

    #[test]
    fn bell_hook_fires_on_a_rise_and_rate_limits_a_burst() {
        // Counts [0,1,1,2,3] at times [0,0,10,20,1500] spawn at index 1 and 4 only — the
        // first rise fires, the rises inside the 1 s window coalesce, the one past it fires.
        let t0 = Instant::now();
        let at = |ms| t0 + Duration::from_millis(ms);
        let mut h = BellHook::new("true");
        let counts = [0u64, 1, 1, 2, 3];
        let times = [0u64, 0, 10, 20, 1500];
        let fired: Vec<bool> = counts
            .iter()
            .zip(times.iter())
            .map(|(&c, &t)| h.observe(c, at(t)))
            .collect();
        assert_eq!(fired, [false, true, false, false, true]);
        // No rise, no spawn — even long after the window.
        assert!(!h.observe(3, at(10_000)));
    }

    #[test]
    fn bell_hook_command_scrubs_parent_koh_vars_and_exports_its_own() {
        // Given a parent environment holding KOH_* vars, the hook's child sees none of them,
        // keeps the rest (PATH, HOME), and gets KOH_BELL_COUNT / KOH_TITLE. The command builder takes the parent env explicitly, so
        // this needs no process-global `set_var`.
        use std::ffi::OsString;
        let dir = crate::test_runtime::scratch("bell-env");
        let out = dir.join("env.txt");
        let hook = BellHook::new(format!("env > '{}'", out.display()));
        let parent_env = [
            ("KOH_DNS", "1.1.1.1"),
            ("KOH_LOG", "/tmp/x"),
            ("PATH", "/usr/bin:/bin"),
            ("HOME", "/nonexistent"),
        ]
        .into_iter()
        .map(|(k, v)| (OsString::from(k), OsString::from(v)));
        let status = hook
            .command(42, "a title", parent_env)
            .status()
            .expect("spawn env");
        let content = std::fs::read_to_string(&out).unwrap_or_default();
        assert!(status.success(), "{content}");
        assert!(content.contains("KOH_BELL_COUNT=42"), "{content}");
        assert!(content.contains("KOH_TITLE=a title"), "{content}");
        assert!(content.contains("PATH=/usr/bin:/bin"), "{content}");
        assert!(
            !content.contains("KOH_DNS"),
            "a parent KOH_* var leaked into the hook's env: {content}"
        );
        assert!(!content.contains("KOH_LOG"), "{content}");
    }

    #[test]
    fn bell_hook_prime_swallows_the_count_it_is_seeded_with_but_not_later_rises() {
        // The first synced frame's cumulative count is not a new bell; a later rise is.
        // Priming again is a no-op (a reconnect keeps counting from where it was).
        let t0 = Instant::now();
        let later = t0 + Duration::from_secs(5);
        let mut h = BellHook::new("true");
        h.prime(5);
        assert!(!h.observe(5, t0), "the primed count is not a rise");
        assert!(h.observe(6, t0), "a rise past the primed count fires");
        h.prime(100);
        assert!(
            h.observe(7, later),
            "a second prime is ignored once a count was seen"
        );
        // observe() alone also primes: a hook that never saw prime() keeps today's behaviour.
        let mut g = BellHook::new("true");
        assert!(
            g.observe(3, t0),
            "with no prime, the first rise from 0 fires"
        );
        g.prime(50);
        assert!(g.observe(4, later), "prime after observe is a no-op");
    }
}
