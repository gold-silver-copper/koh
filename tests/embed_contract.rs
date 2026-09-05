//! Consumer contract tests: no transport-specific types, input readers, or personal keys.
#![allow(clippy::panic_in_result_fn, clippy::expect_used)]

use koh::client::{ClientTerminal, ConnectConfig};
use koh::embed::{Connection, NetworkProfile, Server};
use koh::identity::Identity;
use koh::predict::Overlay;
use koh::server::{ClientId, SessionHost};
use koh::ssp::testkit::GridState;
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

const PROTOCOL: &[u8] = b"koh/embed-contract/1";

struct Host(Option<Arc<Mutex<Vec<u8>>>>);
impl SessionHost for Host {
    type State = GridState;
    fn snapshot(&mut self) -> GridState {
        GridState::default()
    }
    fn input(&mut self, bytes: &[u8]) {
        if let Some(received) = &self.0 {
            received
                .lock()
                .expect("received bytes")
                .extend_from_slice(bytes);
        }
    }
    fn resize(&mut self, _: ClientId, _: u16, _: u16) {}
    fn stamp_echo_ack(state: &mut GridState, ack: u64) {
        state.echo_ack = ack;
    }
    fn alive(&self) -> bool {
        true
    }
}

fn config(server: &Server) -> ConnectConfig {
    ConnectConfig {
        server: server.endpoint_id().to_owned(),
        direct: Some(server.direct_addr().into()),
        key_file: None,
        relay_url: None,
        clipboard: false,
        bell_command: None,
    }
}

async fn connect(server: &Server, identity: &Identity) -> anyhow::Result<Connection> {
    tokio::time::timeout(
        Duration::from_secs(3),
        Box::pin(Connection::connect(&config(server), PROTOCOL, identity)),
    )
    .await?
}

#[tokio::test]
async fn admission_and_capacity_are_enforced_by_the_public_boundary() -> anyhow::Result<()> {
    let allowed = Identity::generate();
    let outsider = Identity::generate();
    let mut server = Server::bind(
        Identity::generate(),
        &BTreeSet::from([allowed.endpoint_id()]),
        PROTOCOL,
        NetworkProfile::Local,
        1,
        || Ok(Host(None)),
    )
    .await?;
    assert!(connect(&server, &outsider).await.is_err());
    let first = connect(&server, &allowed).await?;
    // Capacity is occupied by the admitted connection even before the application starts run().
    assert!(connect(&server, &allowed).await.is_err());
    first.close().await;
    tokio::time::timeout(Duration::from_secs(3), async {
        while server.active_tasks() != 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    let second = connect(&server, &allowed).await?;
    second.close().await;
    server.close();
    assert_eq!(server.active_tasks(), 0);
    Ok(())
}

struct Terminal {
    rendered: Arc<Mutex<Option<tokio::sync::oneshot::Sender<()>>>>,
    dropped: Arc<AtomicBool>,
}
impl ClientTerminal<GridState> for Terminal {
    fn render(&mut self, _: &GridState, _: &Overlay, _: Option<&str>) -> std::io::Result<()> {
        let sender = self
            .rendered
            .lock()
            .map_err(|_| std::io::Error::other("render notification poisoned"))?
            .take();
        if let Some(sender) = sender {
            let _ = sender.send(());
        }
        Ok(())
    }
    fn size(&self) -> std::io::Result<(u16, u16)> {
        Ok((24, 80))
    }
}
impl Drop for Terminal {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn cancellation_restores_application_terminal_and_releases_network_capacity(
) -> anyhow::Result<()> {
    let identity = Identity::generate();
    let mut server = Server::bind(
        Identity::generate(),
        &BTreeSet::from([identity.endpoint_id()]),
        PROTOCOL,
        NetworkProfile::Local,
        1,
        || Ok(Host(None)),
    )
    .await?;
    let connection = connect(&server, &identity).await?;
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let dropped = Arc::new(AtomicBool::new(false));
    let terminal = Terminal {
        rendered: Arc::new(Mutex::new(Some(ready_tx))),
        dropped: Arc::clone(&dropped),
    };
    let (_input, input_rx) = tokio::sync::mpsc::channel(1);
    let (_resize, resize_rx) = tokio::sync::mpsc::channel(1);
    let cancel = CancellationToken::new();
    let run = connection.run(terminal, input_rx, resize_rx, cancel.clone(), None);
    let stop = async {
        ready_rx.await?;
        cancel.cancel();
        Ok::<(), anyhow::Error>(())
    };
    let (outcome, ()) = tokio::time::timeout(
        Duration::from_secs(5),
        Box::pin(async { tokio::try_join!(run, stop) }),
    )
    .await??;
    assert_eq!(outcome, None);
    assert!(dropped.load(Ordering::SeqCst));
    tokio::time::timeout(Duration::from_secs(3), async {
        while server.active_tasks() != 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    // The same identity may attach again; application workspace shutdown was never requested.
    connect(&server, &identity).await?.close().await;
    server.close();
    assert_eq!(server.active_tasks(), 0);
    Ok(())
}

#[tokio::test]
async fn embedded_input_does_not_interpret_standalone_escape_keys() -> anyhow::Result<()> {
    let identity = Identity::generate();
    let received = Arc::new(Mutex::new(Vec::new()));
    let host_bytes = Arc::clone(&received);
    let mut server = Server::bind(
        Identity::generate(),
        &BTreeSet::from([identity.endpoint_id()]),
        PROTOCOL,
        NetworkProfile::Local,
        1,
        move || Ok(Host(Some(Arc::clone(&host_bytes)))),
    )
    .await?;
    let connection = connect(&server, &identity).await?;
    let terminal = Terminal {
        rendered: Arc::new(Mutex::new(None)),
        dropped: Arc::new(AtomicBool::new(false)),
    };
    let (input, input_rx) = tokio::sync::mpsc::channel(1);
    let (_resize, resize_rx) = tokio::sync::mpsc::channel(1);
    let cancel = CancellationToken::new();
    let bytes = b"before\x1e.\x1e\x1aafter";
    input.send(bytes.to_vec()).await?;
    let run = connection.run(terminal, input_rx, resize_rx, cancel.clone(), None);
    let observe = async {
        loop {
            if received.lock().expect("received bytes").as_slice() == bytes {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        cancel.cancel();
        Ok::<(), anyhow::Error>(())
    };
    tokio::time::timeout(
        Duration::from_secs(5),
        Box::pin(async { tokio::try_join!(run, observe) }),
    )
    .await??;
    server.close();
    Ok(())
}
