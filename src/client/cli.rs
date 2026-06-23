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
use clap::{Args, ValueEnum};
use secrecy::SecretString;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::client::{run_client, ClientTerminal, IrohConnector, TerminaTerminal};

#[derive(Copy, Clone, Debug, ValueEnum)]
enum PredictMode {
    Always,
    Never,
    Adaptive,
}

impl From<PredictMode> for DisplayPreference {
    fn from(m: PredictMode) -> Self {
        match m {
            PredictMode::Always => Self::Always,
            PredictMode::Never => Self::Never,
            PredictMode::Adaptive => Self::Adaptive,
        }
    }
}

/// Arguments for `koh connect <server-id>`.
#[derive(Args, Debug)]
pub struct ConnectArgs {
    /// Server endpoint id to connect to.
    server: String,

    /// Path to the client's persistent secret key (its endpoint id must be on the server's allowlist).
    #[arg(long)]
    key_file: Option<PathBuf>,

    /// Prediction display policy.
    #[arg(long, value_enum, default_value_t = PredictMode::Adaptive)]
    predict: PredictMode,

    /// Dial the server at a direct socket address (LAN / loopback; no relay or discovery).
    #[arg(long, value_name = "IP:PORT", conflicts_with = "relay_url")]
    direct: Option<SocketAddr>,

    /// Dial the server via a self-hosted relay URL instead of n0's public relays.
    #[arg(long, value_name = "URL")]
    relay_url: Option<String>,

    /// Shared passphrase, if the server requires one. Prefer $KOH_PASSPHRASE over this flag:
    /// a command-line argument is visible in the process table, an env var is not.
    #[arg(long)]
    passphrase: Option<String>,
}

/// Arguments for `koh id`.
#[derive(Args, Debug)]
pub struct IdArgs {
    /// Path to the client's persistent secret key.
    #[arg(long)]
    key_file: Option<PathBuf>,
}

fn default_key_file() -> PathBuf {
    crate::transport_iroh::default_key_path("client")
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
pub fn run_id(args: IdArgs) -> anyhow::Result<()> {
    let key_file = args.key_file.unwrap_or_else(default_key_file);
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
/// Returns the remote shell's exit code if the session ended because the shell exited.
pub async fn connect(args: ConnectArgs) -> anyhow::Result<Option<u32>> {
    // The TUI owns the terminal, so logs go to a file (set $KOH_LOG) to avoid corrupting it.
    if let Ok(path) = std::env::var("KOH_LOG") {
        if let Ok(file) = std::fs::File::create(&path) {
            tracing_subscriber::fmt()
                .with_writer(std::sync::Mutex::new(file))
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| "koh=debug".into()),
                )
                .init();
        }
    }

    // koh assumes a UTF-8 terminal (the predictor reassembles UTF-8 graphemes; the renderer emits
    // UTF-8). Warn — but don't refuse, unlike mosh — if the locale looks non-UTF-8, so mojibake is
    // diagnosable rather than mysterious.
    warn_if_locale_not_utf8();

    let key_file = args.key_file.clone().unwrap_or_else(default_key_file);
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
    // Optional passphrase second factor (no-op if the server doesn't require one). Held as a
    // SecretString (zeroized on drop, never logged) and shared with the connector so it survives
    // across reconnect dials; exposed as a &str only at the KDF call inside the handshake.
    let passphrase = std::sync::Arc::new(
        args.passphrase
            .clone()
            .or_else(|| std::env::var("KOH_PASSPHRASE").ok())
            .map(SecretString::from),
    );
    // One connector dials the server (and replays the handshake) for the initial connection and for
    // every transparent reconnect. The first dial happens here — before raw mode — so a bad-id or
    // wrong-passphrase error prints cleanly; later drops are re-dialed from inside run_client.
    let connector = IrohConnector::new(endpoint.clone(), target, passphrase);
    let channel = connector.connect().await?;
    eprintln!("connected. (Ctrl-^ then . to disconnect)");

    // Arm graceful shutdown BEFORE entering raw mode, so there's no window where a fatal signal —
    // SIGTERM (`kill`), SIGINT (`kill -INT`; in raw mode Ctrl-C is a forwarded byte, not a signal),
    // or SIGHUP (the controlling terminal closed) — kills us at default disposition with the TTY
    // already raw. Cancelling the token makes run_client return, which drops `term` and restores the
    // terminal; if a signal lands during setup below, the first loop iteration returns immediately.
    let shutdown = CancellationToken::new();
    spawn_signal_shutdown(shutdown.clone())?;

    // --- real terminal I/O wiring (termina: raw mode + alt screen, restored on drop) ---
    let term = TerminaTerminal::enter().context("entering raw mode / alt screen")?;
    let (rows, cols) = term.size().unwrap_or((24, 80));

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

    let result = run_client(
        channel,
        connector,
        args.predict.into(),
        (rows, cols),
        input_rx,
        resize_rx,
        term,
        shutdown,
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
