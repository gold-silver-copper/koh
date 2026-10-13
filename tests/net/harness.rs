//! A real koh server and client on the fault link.
//!
//! The server is `koh serve`'s accept pipeline ([`serve_endpoint`]); the client is `koh connect`'s
//! reconnecting loop ([`run_client`]) with a terminal that records every painted screen. Tests
//! type through the client and watch what it paints.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointId, SecretKey};
use koh::client::{run_client, BellHook, ClientTerminal, IrohConnector};
use koh::predict::Overlay;
use koh::server::cli::{serve_endpoint, Hosting, ServeConfig};
use koh::terminal::{Size, TerminalScreen};
use koh::transport_iroh::generate_secret_key;
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
        Self::start_as(net, generate_secret_key()?, allow, command).await
    }

    /// Start a server as `secret`: given the secret of a stopped one, the same server restarted.
    pub async fn start_as(
        net: &FaultNet,
        secret: SecretKey,
        allow: &[EndpointId],
        command: &[&str],
    ) -> anyhow::Result<Self> {
        let id = secret.public();
        let endpoint = net.endpoint(secret, true).await?;
        let config = ServeConfig {
            allow: allow.to_vec(),
            command: command.iter().map(|arg| (*arg).to_owned()).collect(),
            launcher: koh::pty::Launcher::isolated(env!("CARGO_BIN_EXE_koh"), koh_testkit::home!()),
            ..ServeConfig::default()
        };
        let hosting = Hosting::from_config(&config)?;
        let shutdown = CancellationToken::new();
        let task = koh_testkit::spawn(serve_endpoint(endpoint, hosting, shutdown.clone()));
        Ok(Self { id, shutdown, task })
    }

    /// Shut the server down, as `koh serve` on a signal: what the accept loop returned, an error
    /// if it panicked or did not stop within 5 s.
    pub async fn stop(self) -> anyhow::Result<()> {
        self.shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(5), self.task).await??
    }
}

/// What the client has painted: the screen text, the predicted glyphs drawn over it, and its
/// status line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Painted {
    pub text: String,
    pub predicted: String,
    pub status: Option<String>,
}

/// How a test client runs.
#[derive(Default)]
pub struct Options {
    pub bell: Option<BellHook>,
    /// When the client says it dialed; `None` is now. Earlier, as though the client were frozen
    /// between dialing and running its loop.
    pub dialed_at: Option<std::time::SystemTime>,
}

/// The client's terminal: records each painted screen, at a size the test can change.
struct Recorder {
    painted: watch::Sender<Painted>,
    history: Arc<Mutex<Vec<Painted>>>,
    size: Arc<Mutex<Size>>,
}

/// The glyphs a prediction overlay draws, row by row.
fn predicted_glyphs(overlay: &Overlay, Size { rows, cols }: Size) -> String {
    let mut glyphs = String::new();
    for row in 0..rows {
        for col in 0..cols {
            if let Some(cell) = overlay.cell(row, col) {
                glyphs.push_str(cell.text());
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
        };
        let changed = self.painted.send_if_modified(|last| {
            let changed = *last != painted;
            if changed {
                last.clone_from(&painted);
            }
            changed
        });
        if changed {
            self.history
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(painted);
        }
        Ok(())
    }

    fn size(&self) -> std::io::Result<Size> {
        Ok(*self.size.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

/// A running `koh connect` on the fault link.
pub struct Client {
    pub id: EndpointId,
    input: mpsc::Sender<Vec<u8>>,
    resize: mpsc::Sender<()>,
    size: Arc<Mutex<Size>>,
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
        let first = channel.0.clone();
        let size = Arc::new(Mutex::new(Size::new(24, 80)));
        let (painted_tx, painted) = watch::channel(Painted {
            text: String::new(),
            predicted: String::new(),
            status: None,
        });
        let history = Arc::new(Mutex::new(Vec::new()));
        let term = Recorder {
            painted: painted_tx,
            history: history.clone(),
            size: size.clone(),
        };
        // As koh's own stdin reader (`client::io`): at most 64 reads waiting, so what is typed
        // waits behind no more than the real client would let pile up.
        let (input, input_rx) = mpsc::channel(64);
        let (resize, resize_rx) = mpsc::channel(8);
        let task = koh_testkit::spawn(run_client(
            channel,
            options.dialed_at.unwrap_or_else(std::time::SystemTime::now),
            connector,
            Size::new(24, 80),
            false,
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
        *self.size.lock().unwrap_or_else(PoisonError::into_inner) = Size::new(rows, cols);
        Ok(self.resize.send(()).await?)
    }

    /// Whether the first connection closes within `within`: the client dropped it to reconnect.
    pub async fn first_connection_closes(&self, within: Duration) -> bool {
        tokio::time::timeout(within, self.first.closed())
            .await
            .is_ok()
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

    /// Type `typed` and wait until the screen shows `shown`, for up to 20 s: whether it did.
    pub async fn ran(&mut self, typed: &[u8], shown: &str) -> bool {
        self.send(typed).await.is_ok()
            && self
                .wait_until(Duration::from_secs(20), |t| t.contains(shown))
                .await
                .is_some()
    }

    /// Type `typed` until the screen satisfies `done`, for up to 30 s: what typing during a
    /// reconnect needs, since the client drops it.
    pub async fn retype_until(
        &mut self,
        typed: &[u8],
        done: impl Fn(&str) -> bool + Sync,
    ) -> Option<Painted> {
        for _ in 0..150 {
            let _ = self.send(typed).await;
            if let Some(painted) = self.wait_until(Duration::from_millis(200), &done).await {
                return Some(painted);
            }
        }
        None
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

    /// Type the quit escape and wait up to `within` for the loop to return, as only a live one
    /// does on it.
    pub async fn quit(self, within: Duration) -> Option<anyhow::Result<Option<u32>>> {
        self.send(&[0x1e, b'.']).await.ok()?;
        self.exit(within).await
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

/// A server hosting `command` for one client, and that client's endpoint, to connect (and
/// reconnect) with [`Client::connect_on`].
pub async fn hosting(net: &FaultNet, command: &[&str]) -> anyhow::Result<(Server, Endpoint)> {
    let secret = identity()?;
    let server = Server::start(net, &[secret.public()], command).await?;
    Ok((server, net.endpoint(secret, false).await?))
}

/// A session: one server hosting `command` for one connected client.
pub async fn session(net: &FaultNet, command: &[&str]) -> anyhow::Result<(Server, Client)> {
    let (server, endpoint) = hosting(net, command).await?;
    let client = Client::connect_on(endpoint, server.id, Options::default()).await?;
    Ok((server, client))
}
