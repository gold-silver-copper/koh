//! # rmosh-client
//!
//! The client end of an rmosh session: connects to a server by endpoint id, captures local
//! keystrokes (raw stdin passthrough — byte-perfect), synchronizes the remote screen over
//! QUIC datagrams, speculatively echoes typing, and renders with termina. The session loop
//! itself lives in the library ([`rmosh_client::run_client`]); this binary wires up the real
//! terminal I/O. Press the escape prefix `Ctrl-^` then `.` to disconnect.

use std::io::Read;
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, ValueEnum};
use rmosh_client::{run_client, ClientTerminal, TerminaTerminal};
use rmosh_predict::DisplayPreference;
use rmosh_transport_iroh::{
    bind_endpoint, bind_endpoint_local, bind_endpoint_with_relay, direct_addr, format_endpoint_id,
    load_or_create_secret_key, parse_endpoint_id, parse_relay_url, relay_addr, ALPN,
};
use secrecy::{ExposeSecret, SecretString};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc;

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

#[derive(Parser, Debug)]
#[command(name = "rmosh-client", about = "mosh-over-iroh client")]
struct Args {
    /// Server endpoint id to connect to.
    #[arg(required_unless_present = "show_id")]
    server: Option<String>,

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

    /// Print this client's endpoint id (to add to the server's --allow list) and exit.
    #[arg(long)]
    show_id: bool,

    /// Shared passphrase, if the server requires one. Prefer $RMOSH_PASSPHRASE over this flag:
    /// a command-line argument is visible in the process table, an env var is not.
    #[arg(long)]
    passphrase: Option<String>,
}

fn default_key_file() -> PathBuf {
    directories::ProjectDirs::from("", "", "rmosh").map_or_else(
        || PathBuf::from("rmosh-client.key"),
        |d| d.config_dir().join("client.key"),
    )
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match real_main().await {
        // Exit with the remote shell's status (POSIX wait status is 8-bit).
        Ok(Some(code)) => std::process::ExitCode::from(code as u8),
        Ok(None) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("rmosh-client: {e:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// The real client entry point; returns the remote shell's exit code if the session ended
/// because the shell exited.
async fn real_main() -> anyhow::Result<Option<u32>> {
    if let Ok(path) = std::env::var("RMOSH_LOG") {
        if let Ok(file) = std::fs::File::create(&path) {
            tracing_subscriber::fmt()
                .with_writer(std::sync::Mutex::new(file))
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| "rmosh=debug".into()),
                )
                .init();
        }
    }

    let args = Args::parse();
    let key_file = args.key_file.clone().unwrap_or_else(default_key_file);
    let secret = load_or_create_secret_key(&key_file)
        .with_context(|| format!("loading client key from {}", key_file.display()))?;
    let my_id = secret.public();

    if args.show_id {
        println!("{}", format_endpoint_id(&my_id));
        return Ok(None);
    }

    #[expect(
        clippy::expect_used,
        reason = "clap marks `server` required_unless_present=\"show_id\"; the --show-id branch \
                  returned above, so reaching here guarantees Some"
    )]
    let server = args
        .server
        .clone()
        .expect("clap requires server unless --show-id");
    let server_id = parse_endpoint_id(&server).context("parsing server endpoint id")?;

    eprintln!("rmosh-client id: {}", format_endpoint_id(&my_id));
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
    let conn = endpoint
        .connect(target, ALPN)
        .await
        .context("connecting to server (is your id on its allowlist?)")?;

    // Optional passphrase second factor (no-op if the server doesn't require one). Runs on the
    // raw connection before it's wrapped, since the handshake borrows &conn. Held as a
    // SecretString (zeroized on drop, never logged) and exposed as a &str only at the KDF call.
    let passphrase: Option<SecretString> = args
        .passphrase
        .clone()
        .or_else(|| std::env::var("RMOSH_PASSPHRASE").ok())
        .map(SecretString::from);
    rmosh_transport_iroh::auth::handshake_client(
        &conn,
        passphrase.as_ref().map(SecretString::expose_secret),
    )
    .await
    .context("passphrase handshake (wrong or missing --passphrase?)")?;
    eprintln!("connected. (Ctrl-^ then . to disconnect)");

    let channel = rmosh_transport_iroh::IrohChannel::new(conn);

    // --- real terminal I/O wiring (termina: raw mode + alt screen, restored on drop) ---
    let term = TerminaTerminal::enter().context("entering raw mode / alt screen")?;
    let (rows, cols) = term.size().unwrap_or((24, 80));

    // Raw stdin reader (byte-perfect passthrough) on a dedicated blocking thread.
    let (input_tx, input_rx) = mpsc::channel::<Vec<u8>>(64);
    std::thread::Builder::new()
        .name("rmosh-stdin".into())
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
        args.predict.into(),
        rows,
        cols,
        input_rx,
        resize_rx,
        term,
    )
    .await;
    // `term` is moved into run_client and dropped there, restoring the terminal.

    endpoint.close().await;
    result
}
