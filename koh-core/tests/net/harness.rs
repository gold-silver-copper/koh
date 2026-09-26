//! A real koh server and client on the fault link.
//!
//! The server is `koh serve`'s accept pipeline ([`serve_endpoint`]); the client is `koh connect`'s
//! reconnecting loop ([`run_client`]) with a terminal that records every painted screen. Tests
//! type through the client and watch what it paints.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointId, SecretKey};
use koh_core::client::{run_client, BellHook, ClientTerminal, IrohConnector};
use koh_core::predict::{DisplayPreference, Overlay};
use koh_core::server::cli::{serve_endpoint, Hosting, ServeConfig};
use koh_core::terminal::TerminalScreen;
use koh_core::transport_iroh::{format_endpoint_id, generate_secret_key};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::link::FaultNet;

/// A running `koh serve` on the fault link.
pub struct Server {
    pub id: EndpointId,
    shutdown: CancellationToken,
    task: JoinHandle<anyhow::Result<()>>,
}

impl Server {
    /// Start a server that hosts `command` for the clients in `allow`.
    pub async fn start(
        net: &FaultNet,
        allow: &[EndpointId],
        command: &[&str],
    ) -> anyhow::Result<Self> {
        let secret = generate_secret_key()?;
        let id = secret.public();
        let endpoint = net.endpoint(secret, true).await?;
        let config = ServeConfig {
            allow: allow.iter().map(format_endpoint_id).collect(),
            command: command.iter().map(|arg| (*arg).to_owned()).collect(),
            scrollback: 0,
            launcher: koh_core::pty::Launcher::new(env!("CARGO_BIN_EXE_koh-launch")),
            ..ServeConfig::default()
        };
        let hosting = Hosting::from_config(&config)?;
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(serve_endpoint(endpoint, hosting, shutdown.clone()));
        Ok(Self { id, shutdown, task })
    }

    pub async fn stop(self) {
        self.shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), self.task).await;
    }
}

/// What the client has painted: the screen text, the predicted glyphs drawn over it, its status
/// line, and when any of them last changed.
#[derive(Clone, Debug)]
pub struct Painted {
    pub text: String,
    pub predicted: String,
    pub status: Option<String>,
    pub at: Instant,
}

/// How a test client runs.
#[derive(Default)]
pub struct Options {
    pub bell: Option<BellHook>,
    /// Whether to predict; `None` is `DisplayPreference::Never`.
    pub predict: Option<DisplayPreference>,
}

/// The client's terminal: records each painted screen, at a size the test can change.
struct Recorder {
    painted: watch::Sender<Painted>,
    history: Arc<Mutex<Vec<Painted>>>,
    size: Arc<Mutex<(u16, u16)>>,
}

/// The glyphs a prediction overlay draws, row by row.
fn predicted_glyphs(overlay: &Overlay, (rows, cols): (u16, u16)) -> String {
    let mut glyphs = String::new();
    for row in 0..rows {
        for col in 0..cols {
            if let Some(cell) = overlay.cell(row, col) {
                glyphs.push_str(&cell.glyph);
            }
        }
    }
    glyphs
}

impl ClientTerminal for Recorder {
    fn render(
        &mut self,
        state: &TerminalScreen,
        overlay: &Overlay,
        status: Option<&str>,
    ) -> std::io::Result<()> {
        let painted = Painted {
            text: state.screen().contents(),
            predicted: predicted_glyphs(overlay, state.size()),
            status: status.map(str::to_owned),
            at: Instant::now(),
        };
        let changed = self.painted.send_if_modified(|last| {
            if (&last.text, &last.predicted, &last.status)
                == (&painted.text, &painted.predicted, &painted.status)
            {
                return false;
            }
            *last = painted.clone();
            true
        });
        if changed {
            self.history
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(painted);
        }
        Ok(())
    }

    fn size(&self) -> std::io::Result<(u16, u16)> {
        Ok(*self.size.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

/// A running `koh connect` on the fault link.
pub struct Client {
    pub id: EndpointId,
    input: mpsc::Sender<Vec<u8>>,
    resize: mpsc::Sender<()>,
    size: Arc<Mutex<(u16, u16)>>,
    painted: watch::Receiver<Painted>,
    history: Arc<Mutex<Vec<Painted>>>,
    /// The first connection, so a test can cut it and watch the client reconnect.
    first: Connection,
    task: JoinHandle<anyhow::Result<Option<u32>>>,
}

impl Client {
    /// Dial `server` as `secret` from a fresh endpoint and run the client loop.
    pub async fn connect(
        net: &FaultNet,
        secret: SecretKey,
        server: EndpointId,
    ) -> anyhow::Result<Self> {
        let endpoint = net.endpoint(secret, false).await?;
        Self::connect_on(endpoint, server, Options::default()).await
    }

    /// Dial `server` from `endpoint` (so several connections share one client identity) and run
    /// the client loop.
    pub async fn connect_on(
        endpoint: Endpoint,
        server: EndpointId,
        options: Options,
    ) -> anyhow::Result<Self> {
        let id = endpoint.id();
        let connector = IrohConnector::new(endpoint, FaultNet::addr(server));
        let channel = connector.connect().await?;
        let first = channel.connection().clone();
        let size = Arc::new(Mutex::new((24, 80)));
        let (painted_tx, painted) = watch::channel(Painted {
            text: String::new(),
            predicted: String::new(),
            status: None,
            at: Instant::now(),
        });
        let history = Arc::new(Mutex::new(Vec::new()));
        let term = Recorder {
            painted: painted_tx,
            history: history.clone(),
            size: size.clone(),
        };
        let (input, input_rx) = mpsc::channel(1024);
        let (resize, resize_rx) = mpsc::channel(8);
        let task = tokio::spawn(run_client(
            channel,
            connector,
            options.predict.unwrap_or(DisplayPreference::Never),
            (24, 80),
            input_rx,
            resize_rx,
            term,
            CancellationToken::new(),
            options.bell,
        ));
        Ok(Self {
            id,
            input,
            resize,
            size,
            painted,
            history,
            first,
            task,
        })
    }

    /// Type `bytes`.
    pub async fn send(&self, bytes: &[u8]) -> anyhow::Result<()> {
        Ok(self.input.send(bytes.to_vec()).await?)
    }

    /// Resize the client's terminal to `rows × cols`.
    pub async fn resize_to(&self, rows: u16, cols: u16) -> anyhow::Result<()> {
        *self.size.lock().unwrap_or_else(PoisonError::into_inner) = (rows, cols);
        Ok(self.resize.send(()).await?)
    }

    /// Cut the first connection the way an idle timeout would; the client should reconnect.
    pub fn drop_first_connection(&self) {
        self.first.close(0u32.into(), b"simulated idle timeout");
    }

    /// The screen the client painted last.
    pub fn screen(&self) -> String {
        self.painted.borrow().text.clone()
    }

    /// Everything the client has painted, in order.
    pub fn history(&self) -> Vec<Painted> {
        self.history
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Wait until a painted screen satisfies `done`, up to `timeout`, and return it with the time
    /// it was painted.
    pub async fn wait_until(
        &mut self,
        timeout: Duration,
        done: impl Fn(&str) -> bool + Sync,
    ) -> Option<Painted> {
        self.wait_for(timeout, |painted| done(&painted.text)).await
    }

    /// Wait until what was painted, status line included, satisfies `done`, up to `timeout`.
    pub async fn wait_for(
        &mut self,
        timeout: Duration,
        done: impl Fn(&Painted) -> bool + Send,
    ) -> Option<Painted> {
        let deadline = Instant::now().checked_add(timeout)?;
        loop {
            {
                let painted = self.painted.borrow_and_update();
                if done(&painted) {
                    return Some(painted.clone());
                }
            }
            if tokio::time::timeout_at(deadline, self.painted.changed())
                .await
                .map_or(true, |changed| changed.is_err())
            {
                return None;
            }
        }
    }

    /// End the client (as if its input closed) and return what `run_client` returned.
    pub async fn finish(self) -> Option<anyhow::Result<Option<u32>>> {
        drop(self.input);
        drop(self.resize);
        tokio::time::timeout(Duration::from_secs(5), self.task)
            .await
            .ok()
            .and_then(Result::ok)
    }

    /// Stop the client without a goodbye: its connection is dropped, not closed.
    pub fn abort(self) {
        self.task.abort();
    }

    /// Wait up to `timeout` for the client loop to return on its own (the shell exited).
    pub async fn exit(self, timeout: Duration) -> Option<anyhow::Result<Option<u32>>> {
        let Self { input, task, .. } = self;
        let result = tokio::time::timeout(timeout, task)
            .await
            .ok()
            .and_then(Result::ok);
        drop(input);
        result
    }
}

/// A fresh client identity, to put on a server's allowlist before connecting.
pub fn identity() -> std::io::Result<SecretKey> {
    generate_secret_key()
}

/// A session: one server hosting `command` for one connected client.
pub async fn session(net: &FaultNet, command: &[&str]) -> anyhow::Result<(Server, Client)> {
    let secret = identity()?;
    let server = Server::start(net, &[secret.public()], command).await?;
    let client = Client::connect(net, secret, server.id).await?;
    Ok((server, client))
}

/// The runtime for a test. `#[tokio::test]` is not used: its expansion `allow`s
/// `clippy::expect_used`, which koh-core forbids, and a `forbid` rejects that `allow`.
pub fn runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
}
