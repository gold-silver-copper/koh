//! How the client reads a server's verdict on its connection: a rejection the server sends after
//! the admission ack (the session cap) must fail the client fast, not be taken for a lost link.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context as _;
use koh::client::{run_client, ClientTerminal, IrohConnector};
use koh::predict::{DisplayPreference, Overlay};
use koh::server::cli::{serve_endpoint, Hosting, ServeConfig};
use koh::terminal::{Size, TerminalScreen};
use koh::transport_iroh::admission::await_admission;
use koh::transport_iroh::{bind_endpoint_local, generate_secret_key, loopback_addr, ALPN};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// A terminal that records every status line it is asked to paint.
struct StatusRecorder {
    statuses: Arc<Mutex<Vec<String>>>,
}

impl ClientTerminal for StatusRecorder {
    fn render(
        &mut self,
        _state: &TerminalScreen,
        _overlay: &Overlay<'_>,
        status: Option<&str>,
    ) -> std::io::Result<()> {
        if let Some(s) = status {
            self.statuses
                .lock()
                .map_err(|e| std::io::Error::other(e.to_string()))?
                .push(s.to_owned());
        }
        Ok(())
    }

    fn size(&self) -> std::io::Result<Size> {
        Ok(Size::new(24, 80))
    }
}

fn runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
}

/// A server with `max_sessions = 1`, whose one session is held by another allowed peer. Returns
/// the server's address, the second (allowed) peer's key, the holder's connection, and the
/// shutdown token.
async fn server_at_capacity() -> anyhow::Result<(
    iroh::EndpointAddr,
    iroh::SecretKey,
    iroh::endpoint::Connection,
    iroh::Endpoint,
    CancellationToken,
)> {
    let holder = generate_secret_key()?;
    let second = generate_secret_key()?;
    let server_ep = bind_endpoint_local(generate_secret_key()?, true).await?;
    let addr = loopback_addr(&server_ep);
    let config = ServeConfig {
        allow: vec![holder.public(), second.public()],
        command: vec!["cat".to_owned()],
        scrollback: 0,
        max_sessions: 1,
        launcher: koh::pty::Launcher::new(env!("CARGO_BIN_EXE_koh")),
        ..ServeConfig::default()
    };
    let shutdown = CancellationToken::new();
    tokio::spawn(serve_endpoint(
        server_ep,
        Hosting::from_config(&config)?,
        shutdown.clone(),
    ));
    let holder_ep = bind_endpoint_local(holder, false).await?;
    let held = holder_ep.connect(addr.clone(), ALPN).await?;
    await_admission(&held).await?;
    // Let the registry create the holder's session before the second peer arrives.
    tokio::time::sleep(Duration::from_millis(500)).await;
    Ok((addr, second, held, holder_ep, shutdown))
}

/// The connector's own contract: "A server that rejects us closes the connection instead, which is
/// an error, so a rejected client fails fast". The session-cap rejection is one such close, but it
/// comes after the admission ack, so whether `connect()` sees it is a race with the ack's byte.
/// Dial 50 times; every one must be an error naming the cap.
#[test]
fn connect_to_a_server_at_session_capacity_is_an_error() -> anyhow::Result<()> {
    runtime()?.block_on(async {
        let (addr, second, _held, _holder_ep, shutdown) = server_at_capacity().await?;
        let client_ep = bind_endpoint_local(second, false).await?;
        let connector = IrohConnector::new(client_ep, addr);
        let mut admitted = Vec::new();
        let mut errors = 0u32;
        for _ in 0..50 {
            match connector.connect().await {
                Ok(conn) => {
                    // Show what came after the Ok: the server's close.
                    let closed = conn.closed().await;
                    admitted.push(format!("{closed}"));
                }
                Err(e) => {
                    let e = format!("{e:#}");
                    anyhow::ensure!(e.contains("capacity"), "the error names the cap: {e}");
                    errors = errors.saturating_add(1);
                }
            }
        }
        shutdown.cancel();
        anyhow::ensure!(
            admitted.is_empty(),
            "connect() returned Ok {} of 50 times for a server at session capacity ({errors} \
             errors); each Ok connection then closed with: {:?}",
            admitted.len(),
            admitted.first()
        );
        Ok(())
    })
}

/// End to end: `run_client` against a server at session capacity must return an error naming
/// the cap, not redial forever under a "reconnecting" banner.
#[test]
fn run_client_at_session_capacity_fails_instead_of_redialing() -> anyhow::Result<()> {
    runtime()?.block_on(async {
        let (addr, second, _held, _holder_ep, shutdown) = server_at_capacity().await?;
        let client_ep = bind_endpoint_local(second, false).await?;
        let connector = IrohConnector::new(client_ep.clone(), addr.clone());
        // The first dial as `koh connect` makes it. Whether it sees the cap is a race (see above):
        // take the first dial that the connector admits, as an unlucky `koh connect` would.
        let mut first = None;
        for _ in 0..50 {
            if let Ok(conn) = connector.connect().await {
                first = Some(conn);
                break;
            }
        }
        let Some(first) = first else {
            // The connector refused every dial: the first-dial path already fails fast.
            return Ok(());
        };
        let statuses = Arc::new(Mutex::new(Vec::new()));
        let term = StatusRecorder {
            statuses: statuses.clone(),
        };
        let (_input_tx, input_rx) = mpsc::channel::<Vec<u8>>(8);
        let (_resize_tx, resize_rx) = mpsc::channel::<()>(8);
        let ran = tokio::time::timeout(
            Duration::from_secs(10),
            run_client(
                first,
                std::time::SystemTime::now(),
                connector,
                DisplayPreference::Never,
                Size::new(24, 80),
                None,
                input_rx,
                resize_rx,
                term,
                CancellationToken::new(),
                None,
            ),
        )
        .await;
        shutdown.cancel();
        let seen: Vec<String> = statuses
            .lock()
            .map_err(|e| anyhow::anyhow!("{e}"))?
            .iter()
            .filter(|s| s.contains("reconnect"))
            .take(3)
            .cloned()
            .collect();
        match ran {
            Err(_) => anyhow::bail!(
                "run_client was still redialing a server at session capacity after 10 s; \
                 banners shown: {seen:?}"
            ),
            Ok(Ok(code)) => anyhow::bail!("run_client returned Ok({code:?}) instead of an error"),
            Ok(Err(e)) => {
                let e = format!("{e:#}");
                anyhow::ensure!(e.contains("capacity"), "the error names the cap: {e}");
                anyhow::Ok(())
            }
        }
        .context("server at session capacity")
    })
}
