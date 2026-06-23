//! The `koh connect` / `koh id` command implementations.
//!
//! Dial a server by id and run the reconnecting client session against the real terminal. The
//! session loop itself lives in [`crate::run_client`]; this just wires up the real terminal I/O.

use std::io::Read;
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context;
use clap::{Args, ValueEnum};
use koh_predict::DisplayPreference;
use koh_transport_iroh::{
    bind_endpoint, bind_endpoint_local, bind_endpoint_with_relay, direct_addr, format_endpoint_id,
    load_or_create_secret_key, parse_endpoint_id, parse_relay_url, relay_addr,
};
use secrecy::SecretString;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc;

use crate::{run_client, ClientTerminal, IrohConnector, TerminaTerminal};

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
    directories::ProjectDirs::from("", "", "koh").map_or_else(
        || PathBuf::from("koh-client.key"),
        |d| d.config_dir().join("client.key"),
    )
}

/// `koh id` — print this machine's koh id (to add to a server's `--allow` list) and exit.
pub fn run_id(args: IdArgs) -> anyhow::Result<()> {
    let key_file = args.key_file.unwrap_or_else(default_key_file);
    let secret = load_or_create_secret_key(&key_file)
        .with_context(|| format!("loading client key from {}", key_file.display()))?;
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

    let key_file = args.key_file.clone().unwrap_or_else(default_key_file);
    let secret = load_or_create_secret_key(&key_file)
        .with_context(|| format!("loading client key from {}", key_file.display()))?;
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
    )
    .await;
    // `term` is moved into run_client and dropped there, restoring the terminal.

    endpoint.close().await;
    result
}
