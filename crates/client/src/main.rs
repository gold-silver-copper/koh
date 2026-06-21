//! # rmosh-client
//!
//! The client end of an rmosh session: connects to a server by endpoint id, captures the
//! local keystrokes as a `UserInput` stream, synchronizes the remote screen
//! (`Transport<UserInput, TerminalScreen>`) over QUIC datagrams, speculatively echoes typing
//! via the [`rmosh_predict`] engine, and renders the synced screen with crossterm.
//!
//! Input is **raw stdin passthrough** (byte-perfect: arrow keys, cursor-key modes, UTF-8,
//! bracketed paste all survive) — crossterm is used only for raw mode, the alternate screen,
//! and painting the grid. Resizes come from `SIGWINCH`.
//!
//! Press the escape prefix `Ctrl-^` then `.` to disconnect.

mod render;

use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use clap::{Parser, ValueEnum};
use crossterm::cursor::Show;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use rmosh_input::UserInput;
use rmosh_predict::{DisplayPreference, PredictionEngine};
use rmosh_ssp::{RecvOutcome, Transport, SHUTDOWN_SENTINEL};
use rmosh_terminal::TerminalScreen;
use rmosh_transport_iroh::{
    bind_endpoint, format_endpoint_id, load_or_create_secret_key, parse_endpoint_id, IrohChannel,
    MonoClock, ALPN,
};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc;

/// The escape prefix (Ctrl-^); followed by '.' it disconnects the session.
const ESCAPE_PREFIX: u8 = 0x1e;

#[derive(Copy, Clone, Debug, ValueEnum)]
enum PredictMode {
    Always,
    Never,
    Adaptive,
}

impl From<PredictMode> for DisplayPreference {
    fn from(m: PredictMode) -> Self {
        match m {
            PredictMode::Always => DisplayPreference::Always,
            PredictMode::Never => DisplayPreference::Never,
            PredictMode::Adaptive => DisplayPreference::Adaptive,
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

    /// Print this client's endpoint id (to add to the server's --allow list) and exit.
    #[arg(long)]
    show_id: bool,
}

fn default_key_file() -> PathBuf {
    directories::ProjectDirs::from("", "", "rmosh")
        .map(|d| d.config_dir().join("client.key"))
        .unwrap_or_else(|| PathBuf::from("rmosh-client.key"))
}

/// RAII guard that puts the terminal in raw mode + alternate screen and restores it on drop.
struct TerminalGuard;

impl TerminalGuard {
    fn enter() -> std::io::Result<Self> {
        enable_raw_mode()?;
        crossterm::execute!(std::io::stdout(), EnterAlternateScreen)?;
        Ok(TerminalGuard)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = crossterm::execute!(std::io::stdout(), Show, LeaveAlternateScreen);
        let _ = disable_raw_mode();
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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
        return Ok(());
    }

    let server = args
        .server
        .clone()
        .expect("clap requires server unless --show-id");
    let server_id = parse_endpoint_id(&server).context("parsing server endpoint id")?;

    eprintln!("rmosh-client id: {}", format_endpoint_id(&my_id));
    eprintln!("  (add this to the server with --allow if it isn't already)");
    eprintln!("connecting to {} …", format_endpoint_id(&server_id));

    let endpoint = bind_endpoint(secret, false).await.context("binding endpoint")?;
    let conn = endpoint
        .connect(server_id, ALPN)
        .await
        .context("connecting to server (is your id on its allowlist?)")?;
    eprintln!("connected. (Ctrl-^ then . to disconnect)");

    let result = run_client(conn, args.predict.into()).await;

    endpoint.close().await;
    result
}

async fn run_client(conn: iroh::endpoint::Connection, pref: DisplayPreference) -> anyhow::Result<()> {
    let channel = IrohChannel::new(conn);
    let clock = MonoClock::new();
    let mut transport =
        Transport::<UserInput, TerminalScreen>::new(clock.now_ms(), channel.max_datagram_size());
    transport.set_connected(true);
    let mut predictor = PredictionEngine::new(pref);

    // Enter raw mode / alt screen (restored on drop) before reading stdin.
    let _guard = TerminalGuard::enter().context("entering raw mode")?;
    let mut out = std::io::stdout();

    // Tell the server our real window size right away.
    let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));
    transport.current_mut().push_resize(rows, cols);

    // Raw stdin reader on a dedicated blocking thread (crossterm's event reader can't do
    // byte-perfect passthrough).
    let (stdin_tx, mut stdin_rx) = mpsc::channel::<Vec<u8>>(64);
    std::thread::Builder::new()
        .name("rmosh-stdin".into())
        .spawn(move || {
            let mut stdin = std::io::stdin();
            let mut buf = [0u8; 1024];
            loop {
                match stdin.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if stdin_tx.blocking_send(buf[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        })
        .context("spawning stdin reader")?;

    let mut sigwinch = signal(SignalKind::window_change()).context("installing SIGWINCH handler")?;

    let mut pending_escape = false;
    let mut last_recv = clock.now_ms();
    let mut dirty = true;

    loop {
        let now = clock.now_ms();
        transport.set_mtu(channel.max_datagram_size());
        if let Some(rtt) = channel.rtt_ms() {
            transport.observe_rtt(rtt);
        }
        let wait = transport.wait_time(now);
        let sleep_ms = wait.min(50); // keep the status countdown and predictions lively

        tokio::select! {
            biased;

            // Local keystrokes.
            maybe = stdin_rx.recv() => {
                match maybe {
                    Some(chunk) => {
                        let mut quit = false;
                        let mut fwd: Vec<u8> = Vec::with_capacity(chunk.len());
                        for &b in &chunk {
                            if pending_escape {
                                pending_escape = false;
                                if b == b'.' { quit = true; break; }
                                fwd.push(ESCAPE_PREFIX);
                                fwd.push(b);
                            } else if b == ESCAPE_PREFIX {
                                pending_escape = true;
                            } else {
                                fwd.push(b);
                            }
                        }
                        if quit { break; }
                        if !fwd.is_empty() {
                            // Speculate locally, then queue for transport.
                            predictor.set_local_frame_sent(transport.newest_sent_num());
                            predictor.set_srtt(transport.srtt_ms());
                            let screen = transport.remote_state().screen().clone();
                            for &b in &fwd {
                                predictor.new_user_byte(now, b, &screen);
                            }
                            transport.current_mut().push_bytes(&fwd);
                            dirty = true;
                        }
                    }
                    None => break, // local stdin closed
                }
            }

            // Authoritative screen updates from the server.
            dg = channel.recv() => {
                match dg {
                    Ok(bytes) => {
                        if transport.recv(now, &bytes) == RecvOutcome::NewState {
                            last_recv = now;
                            let echo_ack = transport.remote_state().echo_ack();
                            let screen = transport.remote_state().screen().clone();
                            predictor.set_local_frame_late_acked(echo_ack);
                            predictor.set_srtt(transport.srtt_ms());
                            predictor.cull(now, &screen);
                            dirty = true;
                        }
                    }
                    Err(e) => {
                        tracing::info!(reason = %e, "server closed connection");
                        break;
                    }
                }
            }

            // Local window resized.
            _ = sigwinch.recv() => {
                if let Ok((cols, rows)) = crossterm::terminal::size() {
                    transport.current_mut().push_resize(rows, cols);
                    predictor.reset();
                    dirty = true;
                }
            }

            _ = tokio::time::sleep(Duration::from_millis(sleep_ms)) => {}
        }

        let now = clock.now_ms();
        for datagram in transport.tick(now) {
            channel.send(&datagram);
        }

        // Status overlay when the link has gone quiet (suspend / IP change / loss).
        let staleness = now.saturating_sub(last_recv);
        let status =
            (staleness > 3000).then(|| format!("[rmosh] link down — resuming… {}s", staleness / 1000));

        if dirty || status.is_some() {
            let screen = transport.remote_state().screen();
            let overlay = predictor.overlay(screen);
            render::render(&mut out, screen, &overlay, status.as_deref())?;
            dirty = false;
        }

        // The server signaled a clean shutdown (shell exited): paint the final screen, then go.
        if transport.remote_num() == SHUTDOWN_SENTINEL {
            let screen = transport.remote_state().screen();
            let overlay = rmosh_predict::Overlay::empty();
            let _ = render::render(&mut out, screen, &overlay, Some("[rmosh] session ended"));
            tokio::time::sleep(Duration::from_millis(400)).await;
            break;
        }
    }

    channel.close(0, b"client exit");
    // Terminal restoration happens via TerminalGuard's Drop.
    let _ = writeln!(out);
    Ok(())
}
