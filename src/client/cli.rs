//! The `koh connect` command: dial the server and run [`crate::client::run_client`] on the real
//! terminal.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use iroh::{EndpointId, RelayUrl};
use tokio::signal::unix::SignalKind;
use tokio_util::sync::CancellationToken;

use crate::client::{BackendTerminal, ClientTerminal as _, DefaultBackend, IrohConnector};
use crate::predict::DisplayPreference;
use crate::transport_iroh::{
    bind_endpoint, bind_endpoint_local, bind_endpoint_with_relay, direct_addr, relay_addr,
};

/// The clap-free form of `koh connect`'s arguments.
#[derive(Debug, Clone)]
pub struct ConnectConfig {
    /// Server endpoint id to connect to.
    pub server: EndpointId,
    /// The secret-key file; `None` for the default client key path.
    pub key_file: Option<PathBuf>,
    /// Dial this socket address directly, with no relay or discovery; wins over `relay_url`.
    pub direct: Option<SocketAddr>,
    /// Dial through a self-hosted relay instead of n0's.
    pub relay_url: Option<RelayUrl>,
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
    pub fn new(server: EndpointId) -> Self {
        Self {
            server,
            key_file: None,
            direct: None,
            relay_url: None,
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
    last_count: u64,
    last_spawn_ms: Option<u64>,
    /// Whether a count has been seen (by `prime` or `observe`); `prime` is a no-op afterwards.
    primed: bool,
    /// The instant `observe`'s millisecond clock counts from.
    created: std::time::Instant,
}

/// Minimum spacing between two hook spawns; a burst of bells inside it coalesces into one.
pub const BELL_HOOK_MIN_INTERVAL_MS: u64 = 1_000;

impl BellHook {
    pub fn new(command: impl Into<String>) -> Self {
        Self {
            command: command.into(),
            last_count: 0,
            last_spawn_ms: None,
            primed: false,
            created: std::time::Instant::now(),
        }
    }

    /// Take `count` as seen, without firing, unless a count was seen already.
    pub fn prime(&mut self, count: u64) {
        if !self.primed {
            self.last_count = count;
            self.primed = true;
        }
    }

    /// Note the bell count at `now_ms`; whether to fire: it rose, and the last spawn was at least
    /// [`BELL_HOOK_MIN_INTERVAL_MS`] ago. A rise within that is absorbed, not deferred.
    pub fn observe(&mut self, count: u64, now_ms: u64) -> bool {
        let rose = count > self.last_count;
        self.last_count = count;
        self.primed = true;
        if !rose {
            return false;
        }
        let spaced = self
            .last_spawn_ms
            .is_none_or(|t| now_ms.saturating_sub(t) >= BELL_HOOK_MIN_INTERVAL_MS);
        if spaced {
            self.last_spawn_ms = Some(now_ms);
        }
        spaced
    }

    /// [`observe`](Self::observe) at `now` and, if due, [`fire`](Self::fire).
    pub fn observe_and_fire(&mut self, count: u64, title: &str, now: std::time::Instant) {
        // Milliseconds since the hook was made, saturating after 584 million years.
        let now_ms = u64::try_from(now.saturating_duration_since(self.created).as_millis())
            .unwrap_or(u64::MAX);
        if self.observe(count, now_ms) {
            self.fire(count, title);
        }
    }

    /// The command to spawn, with `parent_env` scrubbed of `KOH_*` (given, so tests can pass their
    /// own).
    pub(crate) fn command(
        &self,
        count: u64,
        title: &str,
        parent_env: impl IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
    ) -> std::process::Command {
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

/// Bind an endpoint for `config` and make the first connection; the connector redials the same
/// target.
async fn dial(
    config: &ConnectConfig,
    identity: &crate::identity::Identity,
) -> anyhow::Result<(iroh::Endpoint, IrohConnector, iroh::endpoint::Connection)> {
    let secret = identity.secret.clone();
    let server = config.server;
    let (endpoint, target) = if let Some(addr) = config.direct {
        (
            bind_endpoint_local(secret, false).await?,
            direct_addr(server, addr),
        )
    } else if let Some(relay) = config.relay_url.clone() {
        let endpoint = bind_endpoint_with_relay(secret, false, relay.clone()).await?;
        (endpoint, relay_addr(server, relay))
    } else {
        (bind_endpoint(secret, false).await?, server.into())
    };
    let connector = IrohConnector::new(endpoint.clone(), target);
    let first = tokio::time::timeout(Duration::from_secs(15), connector.connect())
        .await
        .context("timed out connecting (server unreachable or not responding)")
        .and_then(std::convert::identity);
    match first {
        Ok(channel) => Ok((endpoint, connector, channel)),
        Err(error) => {
            close_endpoint(&endpoint).await;
            Err(error)
        }
    }
}

/// Close `endpoint`, waiting a bounded time for the server to see it.
async fn close_endpoint(endpoint: &iroh::Endpoint) {
    crate::transport_iroh::close_endpoint(endpoint).await;
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
        eprintln!(
            "koh: warning: locale {shown} does not look UTF-8; non-ASCII output may be garbled. \
             Set e.g. LANG=en_US.UTF-8."
        );
    }
}

/// With `$KOH_LOG` set, log to that file at debug level (the TUI owns the terminal). It is made
/// 0600 through its descriptor, existing or not, as debug logs can be sensitive; failing that,
/// nothing is logged.
fn log_to_koh_log() {
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
    let Ok(path) = std::env::var("KOH_LOG") else {
        return;
    };
    let Ok(file) = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
    else {
        return;
    };
    if file
        .set_permissions(std::fs::Permissions::from_mode(0o600))
        .is_err()
    {
        eprintln!("koh: warning: could not set $KOH_LOG to 0600; file logging disabled");
        return;
    }
    crate::log::init(std::sync::Mutex::new(file), tracing::Level::DEBUG);
}

/// The longest the client waits for the user's terminal to answer its start-up questions. A local
/// terminal answers within milliseconds; one that answers nothing leaves the defaults.
const PROBE_WAIT: std::time::Duration = std::time::Duration::from_millis(500);

/// Ask the user's terminal what it draws, speaks and shows (see [`super::probe`]; its colours too if
/// `colours`), and paint and listen accordingly. Its answers are read out of `input`; what was
/// typed meanwhile goes on to the session, first, on the input returned, with the colours to tell
/// the server (`None` if not asked).
async fn probe_terminal<B: crate::client::KohBackend>(
    terminal: &mut BackendTerminal<B>,
    mut input: tokio::sync::mpsc::Receiver<Vec<u8>>,
    colours: bool,
) -> (
    tokio::sync::mpsc::Receiver<Vec<u8>>,
    Option<crate::events::WireColours>,
) {
    let mut replies = super::probe::Replies::default();
    if terminal.ask(&super::probe::queries(colours)).is_ok() {
        let deadline = tokio::time::Instant::now()
            .checked_add(PROBE_WAIT)
            .unwrap_or_else(tokio::time::Instant::now);
        while !replies.done() {
            match tokio::time::timeout_at(deadline, input.recv()).await {
                Ok(Some(bytes)) => replies.push(&bytes),
                Ok(None) | Err(_) => break,
            }
        }
    }
    terminal.set_underline_styles(replies.underline_styles());
    // Scheme reports only matter while colours are told.
    let scheme_reports = colours && replies.scheme_reports();
    if let Err(e) = terminal.turn_on(replies.kitty(), scheme_reports) {
        tracing::warn!(error = %e, "could not set the terminal's keyboard and scheme reports");
    }
    tracing::debug!(
        underline_styles = replies.underline_styles(),
        kitty = replies.kitty(),
        scheme_reports,
        "the user's terminal"
    );
    let told = colours.then(|| replies.colours());
    let typed = replies.typed();
    let (tx, rx) = tokio::sync::mpsc::channel(64);
    tokio::spawn(async move {
        if !typed.is_empty() && tx.send(typed).await.is_err() {
            return;
        }
        while let Some(bytes) = input.recv().await {
            if tx.send(bytes).await.is_err() {
                break;
            }
        }
    });
    (rx, told)
}

/// `koh connect`: the remote shell's exit code if it exited. Takes the process's terminal, stdin
/// and signal handlers for the session.
pub async fn connect(args: ConnectConfig) -> anyhow::Result<Option<u32>> {
    log_to_koh_log();

    warn_if_locale_not_utf8();

    // Held for the session: its lease stops `koh key reset` while it may redial.
    let identity =
        crate::identity::load(&crate::identity::key_path(args.key_file.clone(), "client")?)?;
    let (endpoint, connector, channel) = dial(&args, &identity).await?;
    let dialed_at = std::time::SystemTime::now();
    let shutdown = CancellationToken::new();
    // Armed before raw mode is entered, so an install error surfaces while the terminal is cooked.
    crate::cancel_on_signals(
        &shutdown,
        &[
            SignalKind::terminate(),
            SignalKind::interrupt(),
            SignalKind::hangup(),
        ],
    )
    .context("installing the signal handlers")?;
    let (channels, tasks) = super::spawn_client_io()?;
    let result = async {
        let backend = DefaultBackend::new().context("acquiring the terminal")?;
        let mut terminal = BackendTerminal::enter(backend, args.clipboard)
            .context("entering raw mode / alt screen")?;
        terminal.set_hyperlinks(args.hyperlinks);
        let (input_rx, colours) =
            probe_terminal(&mut terminal, channels.input_rx, args.colours).await;
        let size = terminal.size().unwrap_or(crate::terminal::DEFAULT_SIZE);
        crate::client::run_client(
            channel,
            dialed_at,
            connector,
            DisplayPreference::Always,
            size,
            colours,
            input_rx,
            channels.resize_rx,
            terminal,
            shutdown,
            args.bell_command.map(BellHook::new),
        )
        .await
    }
    .await;
    close_endpoint(&endpoint).await;
    drop(identity);
    super::io::first_error(result, tasks.shutdown().await)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redial_reuses_the_loaded_identity_without_touching_the_key_file() -> anyhow::Result<()> {
        crate::test_runtime::current_thread().block_on(async {
            use crate::transport_iroh::{admission, bind_endpoint_local, generate_secret_key};
            let server = bind_endpoint_local(generate_secret_key()?, true).await?;
            let identity = crate::identity::Identity::generate()?;
            let expected = identity.secret.public();
            let socket = server
                .bound_sockets()
                .into_iter()
                .find(std::net::SocketAddr::is_ipv4)
                .context("server IPv4 socket")?;
            let config = ConnectConfig {
                server: server.id(),
                // Any attempt to reload instead of reusing `identity` would fail here.
                key_file: Some("/nonexistent/koh-redial-test.key".into()),
                direct: Some(([127, 0, 0, 1], socket.port()).into()),
                relay_url: None,
                clipboard: false,
                hyperlinks: false,
                colours: false,
                bell_command: None,
            };
            let peer = server.clone();
            let accept = async move {
                for _ in 0..2 {
                    let connection = peer.accept().await.context("accept connection")?.await?;
                    anyhow::ensure!(
                        connection.remote_id() == expected,
                        "client identity changed"
                    );
                    admission::admit(&connection).await?;
                    connection.closed().await;
                }
                Ok::<_, anyhow::Error>(())
            };
            let client = async {
                let (endpoint, connector, channel) = dial(&config, &identity).await?;
                channel.close(0u32.into(), b"test reconnect");
                // The same connector `run_client` redials with after a link loss.
                let channel = connector.connect().await?;
                channel.close(0u32.into(), b"test done");
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
        let mut h = BellHook::new("true");
        let counts = [0u64, 1, 1, 2, 3];
        let times = [0u64, 0, 10, 20, 1500];
        let fired: Vec<bool> = counts
            .iter()
            .zip(times.iter())
            .map(|(&c, &t)| h.observe(c, t))
            .collect();
        assert_eq!(fired, [false, true, false, false, true]);
        // No rise, no spawn — even long after the window.
        assert!(!h.observe(3, 10_000));
    }

    #[test]
    fn bell_hook_command_scrubs_parent_koh_vars_and_exports_its_own() {
        // Given a parent environment holding KOH_* vars, the hook's child sees none of them,
        // keeps the rest (PATH, HOME), and gets KOH_BELL_COUNT / KOH_TITLE. The command builder takes the parent env explicitly, so
        // this needs no process-global `set_var`.
        use std::ffi::OsString;
        let dir = std::env::temp_dir().join(format!(
            "koh-bell-env-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
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
        let _ = std::fs::remove_dir_all(&dir);
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
        let mut h = BellHook::new("true");
        h.prime(5);
        assert!(!h.observe(5, 0), "the primed count is not a rise");
        assert!(h.observe(6, 0), "a rise past the primed count fires");
        h.prime(100);
        assert!(
            h.observe(7, 5_000),
            "a second prime is ignored once a count was seen"
        );
        // observe() alone also primes: a hook that never saw prime() keeps today's behaviour.
        let mut g = BellHook::new("true");
        assert!(
            g.observe(3, 0),
            "with no prime, the first rise from 0 fires"
        );
        g.prime(50);
        assert!(g.observe(4, 5_000), "prime after observe is a no-op");
    }

    #[test]
    fn connect_config_default_has_no_bell_hook() {
        let server = crate::transport_iroh::generate_secret_key()
            .unwrap()
            .public();
        assert!(ConnectConfig::new(server).bell_command.is_none());
    }
}
