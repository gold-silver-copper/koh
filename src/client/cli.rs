//! The `koh connect` / `koh id` command implementations.
//!
//! Dial a server by id and run the reconnecting client session against the real terminal. The
//! session loop itself lives in [`crate::client::run_client`]; this just wires up the real terminal I/O.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use tokio::signal::unix::{signal, SignalKind};
use tokio_util::sync::CancellationToken;

use crate::client::{BackendTerminal, ClientTerminal as _, DefaultBackend, IrohConnector};
use crate::predict::DisplayPreference;
use crate::transport_iroh::{
    bind_endpoint, bind_endpoint_local, bind_endpoint_with_relay, direct_addr, parse_endpoint_id,
    parse_relay_url, relay_addr, IrohChannel,
};

/// Configuration for [`connect`] — the clap-free, library-facing form of `koh connect`'s
/// arguments. No `Default`: `server` is required.
#[derive(Debug, Clone)]
pub struct ConnectConfig {
    /// Server endpoint id to connect to.
    pub server: String,
    /// Path to the client's persistent secret key (its endpoint id must be on the server's
    /// allowlist). `None` = the platform default client key path.
    pub key_file: Option<PathBuf>,
    /// Dial the server at a direct socket address (LAN / loopback; no relay or discovery).
    /// Takes precedence over `relay_url` if both are set.
    pub direct: Option<SocketAddr>,
    /// Dial the server via a self-hosted relay URL instead of n0's public relays.
    pub relay_url: Option<String>,
    /// Honor remote OSC-52 clipboard writes. Off by default in the CLI (`--clipboard`).
    pub clipboard: bool,
    /// A shell command to run (via `sh -c`) whenever the remote bell count climbs, e.g.
    /// `termux-notification -t "koh bell"`. Detached from the terminal, rate-limited to one spawn
    /// per second; bells that rang before this client attached do not fire it, bells during a
    /// reconnect do. `None` = no hook.
    pub bell_command: Option<String>,
}

impl ConnectConfig {
    /// A config for dialing `server` with every other option at the CLI default.
    pub fn new(server: impl Into<String>) -> Self {
        Self {
            server: server.into(),
            key_file: None,
            direct: None,
            relay_url: None,
            clipboard: false,
            bell_command: None,
        }
    }
}

/// Runs a user command whenever the remote bell rings: `--on-bell` / [`ConnectConfig::bell_command`].
///
/// The decision (`observe`) is pure and rate-limited so it is unit-testable; the spawn is
/// detached — stdin/stdout/stderr on `/dev/null`, since the TUI owns the terminal — with
/// `KOH_BELL_COUNT` and `KOH_TITLE` in the environment and every other `KOH_*` variable scrubbed
/// (the same guard as `pty.rs`). The child is reaped on a background task and never awaited by
/// the session loop.
///
/// The remote bell count is cumulative for the life of the server session, so the hook is
/// [`prime`](Self::prime)d with the count of the first synced frame: bells that rang before you
/// attached do not fire it. The hook outlives a reconnect (it is not re-primed), so bells that
/// rang during an outage do.
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

    /// Seed the hook with the bell count of the first synced frame, without spawning: bells that
    /// rang before this client attached are not "new". A no-op once any count has been seen, so a
    /// reconnect keeps counting from where it was and bells during the outage still fire.
    pub fn prime(&mut self, count: u64) {
        if !self.primed {
            self.last_count = count;
            self.primed = true;
        }
    }

    /// Note the remote bell count at `now_ms`. Returns `true` when the hook should spawn now: the
    /// count climbed since the last observation and at least [`BELL_HOOK_MIN_INTERVAL_MS`] passed
    /// since the last spawn. A rise inside the window is coalesced (absorbed, not deferred).
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

    /// Build the detached command: `sh -c CMD` with `parent_env` minus every `KOH_*` key, plus
    /// `KOH_BELL_COUNT` / `KOH_TITLE`, and all three fds on `/dev/null`. Pure given `parent_env`,
    /// so the scrub is testable with a synthetic environment.
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

    /// Spawn the command detached (never blocks the session loop; the child is reaped by a
    /// background task).
    pub fn fire(&self, count: u64, title: &str) {
        match self.command(count, title, std::env::vars_os()).spawn() {
            Ok(mut child) => {
                // Reap off the async loop; a stuck hook can't wedge the session.
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

/// Bind an endpoint for `config`'s dial mode and make the first, admitted connection. The returned
/// connector redials the same target with the same identity after a link loss.
async fn dial(
    config: &ConnectConfig,
    identity: &crate::identity::Identity,
) -> anyhow::Result<(iroh::Endpoint, IrohConnector, IrohChannel)> {
    let secret = identity.secret.clone();
    let server = parse_endpoint_id(&config.server).context("parsing server endpoint id")?;
    let (endpoint, target) = if let Some(addr) = config.direct {
        (
            bind_endpoint_local(secret, false).await?,
            direct_addr(server, addr),
        )
    } else if let Some(url) = &config.relay_url {
        let relay = parse_relay_url(url)?;
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

/// Close `endpoint`, waiting at most two seconds for the peer to see it.
async fn close_endpoint(endpoint: &iroh::Endpoint) {
    let _ = tokio::time::timeout(Duration::from_secs(2), endpoint.close()).await;
}

/// Spawn a task that cancels `shutdown` on the first fatal signal (SIGTERM / SIGINT / SIGHUP), so
/// the client unwinds cleanly and restores the terminal. Called before raw mode is entered (so the
/// handlers are armed for the entire raw window); an install error surfaces while still cooked.
fn spawn_signal_shutdown(shutdown: CancellationToken) -> anyhow::Result<()> {
    let mut term = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
    let mut intr = signal(SignalKind::interrupt()).context("installing SIGINT handler")?;
    let mut hup = signal(SignalKind::hangup()).context("installing SIGHUP handler")?;
    tokio::spawn(async move {
        tokio::select! {
            _ = term.recv() => {}
            _ = intr.recv() => {}
            _ = hup.recv() => {}
        }
        shutdown.cancel();
    });
    Ok(())
}

/// Warn (once, to stderr) if the locale doesn't look UTF-8. koh assumes UTF-8 end to end; on a
/// legacy locale, output may be mojibake. We only warn — koh still runs — where mosh refuses.
fn warn_if_locale_not_utf8() {
    // `$LC_ALL` overrides `$LC_CTYPE`, which overrides `$LANG` (POSIX precedence).
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

/// `koh connect <server-id>` — connect to a koh server and run the (auto-reconnecting) session.
///
/// Returns the remote shell's exit code if the session ended because the shell exited.
/// Accepts a [`ConnectConfig`] or anything convertible into one.
///
/// Takes over the calling process's terminal (raw mode, alternate screen) and its stdin for the
/// session's lifetime, and installs signal handlers; call it from a binary's main path.
pub async fn connect(config: impl Into<ConnectConfig>) -> anyhow::Result<Option<u32>> {
    let args: ConnectConfig = config.into();
    // The TUI owns the terminal, so logs go to a file (set $KOH_LOG) to avoid corrupting it.
    if let Ok(path) = std::env::var("KOH_LOG") {
        // Create the log owner-only (0600): debug logs can carry sensitive material.
        let created = {
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(&path)
            }
            #[cfg(not(unix))]
            {
                std::fs::File::create(&path)
            }
        };
        if let Ok(file) = created {
            // Tighten to 0600 unconditionally via the fd: the `mode` above only applies when
            // the file is *created*, so a pre-existing looser `$KOH_LOG` (or one a co-tenant planted)
            // would otherwise be reused/truncated with its loose bits intact. `File::set_permissions`
            // fchmods the open fd, so it also avoids re-resolving the path through a symlink. If we
            // CAN'T secure it (e.g. `$KOH_LOG` points at a foreign-owned file → EPERM), don't write
            // potentially-sensitive debug logs into a file we couldn't lock down — warn and skip.
            let secured = {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let ok = file
                        .set_permissions(std::fs::Permissions::from_mode(0o600))
                        .is_ok();
                    if !ok {
                        eprintln!(
                            "koh: warning: could not set $KOH_LOG to 0600; file logging disabled"
                        );
                    }
                    ok
                }
                #[cfg(not(unix))]
                {
                    true
                }
            };
            if secured {
                use tracing_subscriber::layer::SubscriberExt as _;
                use tracing_subscriber::util::SubscriberInitExt as _;
                let _ = tracing_subscriber::registry()
                    .with(tracing_subscriber::fmt::layer().with_writer(std::sync::Mutex::new(file)))
                    .with(crate::log::targets(tracing::Level::DEBUG))
                    .try_init();
            }
        }
    }

    // koh assumes a UTF-8 terminal (the predictor reassembles UTF-8 graphemes; the renderer emits
    // UTF-8). Warn — but don't refuse, unlike mosh — if the locale looks non-UTF-8, so mojibake is
    // diagnosable rather than mysterious.
    warn_if_locale_not_utf8();

    // Held for the whole session: the identity's lease keeps `koh key reset` from deleting the key
    // while this client may still redial with it.
    let identity = crate::identity::load_client(args.key_file.as_deref())?;
    let (endpoint, connector, channel) = dial(&args, &identity).await?;
    let shutdown = CancellationToken::new();
    spawn_signal_shutdown(shutdown.clone())?;
    let (channels, tasks) = super::spawn_client_io()?;
    let result = async {
        let backend = DefaultBackend::new().context("acquiring the terminal")?;
        let terminal = BackendTerminal::enter(backend, args.clipboard)
            .context("entering raw mode / alt screen")?;
        let size = terminal.size().unwrap_or((24, 80));
        crate::client::run_client(
            channel,
            connector,
            DisplayPreference::Always,
            size,
            channels.input_rx,
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
    let cleanup = tasks.shutdown().await;
    match (result, cleanup) {
        (Err(primary), Err(cleanup)) => {
            tracing::warn!(error = ?cleanup, "client I/O cleanup also failed");
            Err(primary)
        }
        (Err(primary), Ok(())) => Err(primary),
        (Ok(_), Err(cleanup)) => Err(cleanup),
        (Ok(value), Ok(())) => Ok(value),
    }
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
                server: server.id().to_string(),
                // Any attempt to reload instead of reusing `identity` would fail here.
                key_file: Some("/nonexistent/koh-redial-test.key".into()),
                direct: Some(([127, 0, 0, 1], socket.port()).into()),
                relay_url: None,
                clipboard: false,
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
                channel.close(0, b"test reconnect");
                // The same connector `run_client` redials with after a link loss.
                let channel = connector.connect().await?;
                channel.close(0, b"test done");
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
        assert!(ConnectConfig::new("abc").bell_command.is_none());
    }
}
