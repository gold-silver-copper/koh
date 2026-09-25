//! A real koh server and client on the fault link.
//!
//! The server is `koh serve`'s accept pipeline ([`serve_endpoint`]); the client is `koh connect`'s
//! reconnecting loop ([`run_client`]) with a terminal that records every painted screen. Tests
//! type through the client and watch what it paints.

use std::time::Duration;

use iroh::{EndpointId, SecretKey};
use koh::client::{run_client, ClientTerminal, IrohConnector};
use koh::predict::{DisplayPreference, Overlay};
use koh::server::cli::{serve_endpoint, Hosting, ServeConfig};
use koh::terminal::TerminalScreen;
use koh::transport_iroh::{format_endpoint_id, generate_secret_key};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::link::FaultNet;

/// The client terminal's size.
const SIZE: (u16, u16) = (24, 80);

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
        let secret = generate_secret_key();
        let id = secret.public();
        let endpoint = net.endpoint(secret, true).await?;
        let config = ServeConfig {
            allow: allow.iter().map(format_endpoint_id).collect(),
            command: command.iter().map(|arg| (*arg).to_owned()).collect(),
            scrollback: 0,
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

/// What the client has painted: the latest screen text and when it last changed.
#[derive(Clone, Debug)]
pub struct Painted {
    pub text: String,
    pub at: Instant,
}

/// The client's terminal: records each painted screen.
struct Recorder {
    painted: watch::Sender<Painted>,
}

impl ClientTerminal for Recorder {
    fn render(
        &mut self,
        state: &TerminalScreen,
        _overlay: &Overlay,
        _status: Option<&str>,
    ) -> std::io::Result<()> {
        let text = state.screen().contents();
        self.painted.send_if_modified(|painted| {
            if painted.text == text {
                return false;
            }
            *painted = Painted {
                text,
                at: Instant::now(),
            };
            true
        });
        Ok(())
    }

    fn size(&self) -> std::io::Result<(u16, u16)> {
        Ok(SIZE)
    }
}

/// A running `koh connect` on the fault link.
pub struct Client {
    pub id: EndpointId,
    input: mpsc::Sender<Vec<u8>>,
    resize: mpsc::Sender<()>,
    painted: watch::Receiver<Painted>,
    task: JoinHandle<anyhow::Result<Option<u32>>>,
}

impl Client {
    /// A fresh client identity, to put on a server's allowlist before [`Client::connect`].
    pub fn identity() -> SecretKey {
        generate_secret_key()
    }

    /// Dial `server` as `secret` and run the client loop.
    pub async fn connect(
        net: &FaultNet,
        secret: SecretKey,
        server: EndpointId,
    ) -> anyhow::Result<Self> {
        let id = secret.public();
        let endpoint = net.endpoint(secret, false).await?;
        let connector = IrohConnector::new(endpoint, FaultNet::addr(server));
        let channel = connector.connect().await?;
        let (painted_tx, painted) = watch::channel(Painted {
            text: String::new(),
            at: Instant::now(),
        });
        let term = Recorder {
            painted: painted_tx,
        };
        let (input, input_rx) = mpsc::channel(1024);
        let (resize, resize_rx) = mpsc::channel(8);
        let task = tokio::spawn(run_client(
            channel,
            connector,
            DisplayPreference::Never,
            SIZE,
            input_rx,
            resize_rx,
            term,
            CancellationToken::new(),
            None,
        ));
        Ok(Self {
            id,
            input,
            resize,
            painted,
            task,
        })
    }

    /// Type `bytes`.
    pub async fn send(&self, bytes: &[u8]) -> anyhow::Result<()> {
        Ok(self.input.send(bytes.to_vec()).await?)
    }

    /// The screen the client painted last.
    pub fn screen(&self) -> String {
        self.painted.borrow().text.clone()
    }

    /// Wait until a painted screen satisfies `done`, up to `timeout`, and return it with the time
    /// it was painted.
    pub async fn wait_until(
        &mut self,
        timeout: Duration,
        done: impl Fn(&str) -> bool,
    ) -> Option<Painted> {
        let deadline = Instant::now() + timeout;
        loop {
            {
                let painted = self.painted.borrow_and_update();
                if done(&painted.text) {
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
}

/// A session: one server hosting `command` for one connected client.
pub async fn session(net: &FaultNet, command: &[&str]) -> anyhow::Result<(Server, Client)> {
    let secret = Client::identity();
    let server = Server::start(net, &[secret.public()], command).await?;
    let client = Client::connect(net, secret, server.id).await?;
    Ok((server, client))
}
