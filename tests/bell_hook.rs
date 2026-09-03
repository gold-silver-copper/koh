//! The client bell hook end to end (KB-01): a real PTY shell rings the bell, the client (over the
//! generic `run_client_with` wiring) runs the hook command, and a burst of bells is rate-limited.

// Integration test: a failed unwrap/expect/assert IS the test failing.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::items_after_statements,
    clippy::default_trait_access,
    clippy::unwrap_in_result,
    reason = "integration test code; panics are assertion failures"
)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use koh::client::{run_client_with, BellHook, ClientTerminal, IrohConnector};
use koh::predict::{DisplayPreference, Overlay};
use koh::server::run_session;
use koh::terminal::TerminalScreen;
use koh::transport_iroh::{bind_endpoint_local, generate_secret_key, loopback_addr};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

struct MockTerminal {
    latest: Arc<Mutex<String>>,
}

impl ClientTerminal<TerminalScreen> for MockTerminal {
    fn render(
        &mut self,
        state: &TerminalScreen,
        _overlay: &Overlay,
        _status: Option<&str>,
    ) -> std::io::Result<()> {
        *self.latest.lock().unwrap() = state.screen().contents();
        Ok(())
    }

    fn size(&self) -> std::io::Result<(u16, u16)> {
        Ok((24, 80))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remote_bell_runs_the_hook_once_per_second_at_most() {
    let server_ep = bind_endpoint_local(generate_secret_key(), true)
        .await
        .expect("bind server");
    let addr = loopback_addr(&server_ep);
    let accept = tokio::spawn(async move {
        while let Some(incoming) = server_ep.accept().await {
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                koh::transport_iroh::admission::admit(&conn)
                    .await
                    .expect("admit");
                let _ = run_session(conn, &["sh".to_owned()], 0).await;
            });
        }
    });

    let tmp = std::env::temp_dir().join(format!("koh-bell-hook-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let log = tmp.join("rang.log");
    // Each spawn appends one line, so the line count is the spawn count.
    let hook = BellHook::new(format!("echo rang $KOH_BELL_COUNT >> '{}'", log.display()));

    let client_ep = bind_endpoint_local(generate_secret_key(), false)
        .await
        .expect("bind client");
    let connector = IrohConnector::new(client_ep, addr);
    let channel = connector.connect().await.expect("connect");
    let latest = Arc::new(Mutex::new(String::new()));
    let term = MockTerminal {
        latest: latest.clone(),
    };
    let (input_tx, input_rx) = mpsc::channel::<Vec<u8>>(8);
    let (_resize_tx, resize_rx) = mpsc::channel::<()>(1);
    let shutdown = CancellationToken::new();
    let client = tokio::spawn(run_client_with(
        channel,
        connector,
        DisplayPreference::Always,
        (24, 80),
        input_rx,
        resize_rx,
        term,
        shutdown.clone(),
        Some(hook),
    ));

    // One bell: the hook fires within the marker deadline.
    input_tx
        .send(b"printf '\\a'; echo BELL_ONE\r".to_vec())
        .await
        .unwrap();
    let mut lines = 0;
    for _ in 0..100 {
        lines = std::fs::read_to_string(&log).map_or(0, |s| s.lines().count());
        if lines >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(lines, 1, "the first bell spawns the hook exactly once");

    // Wait out the rate-limit window, then five bells in one command: at most one more spawn
    // (the burst coalesces), never five.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    input_tx
        .send(b"printf '\\a\\a\\a\\a\\a'; echo BELL_BURST\r".to_vec())
        .await
        .unwrap();
    for _ in 0..30 {
        if latest.lock().unwrap().contains("BELL_BURST") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let lines = std::fs::read_to_string(&log).map_or(0, |s| s.lines().count());
    assert!(
        (2..=3).contains(&lines),
        "a burst of five bells must coalesce to at most one or two spawns, got {lines}"
    );
    let content = std::fs::read_to_string(&log).unwrap();
    assert!(
        content.contains("rang 1"),
        "KOH_BELL_COUNT is exported to the hook: {content:?}"
    );

    shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), client).await;
    accept.abort();
    let _ = std::fs::remove_dir_all(&tmp);
}
