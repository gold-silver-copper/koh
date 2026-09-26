//! Tier 1 end-to-end: the full koh stack over a **real iroh connection**, headless.
//!
//! Two iroh endpoints on loopback (no relay, no second machine), a real PTY-hosted shell on
//! the server, and the real client session loop driven through a mock terminal — exercising
//! the entire path: scripted keystroke → client → input stream → server → PTY → shell echo →
//! fux-vt → frame stream → client render, on the plain loopback path with no fault link in
//! between (the `net` tests add one).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use koh::client::{run_client, ClientTerminal, IrohConnector};
use koh::predict::{DisplayPreference, Overlay};
use koh::server::run_session;
use koh::terminal::TerminalScreen;
use koh::transport_iroh::{
    bind_endpoint_local, generate_secret_key, loopback_addr, IrohChannel, ALPN,
};
use tokio::sync::mpsc;

/// A terminal backend that captures the latest authoritative screen as plain text, so a test
/// can assert on what the user would see — no real TTY involved.
struct MockTerminal {
    latest: Arc<Mutex<String>>,
}

impl ClientTerminal for MockTerminal {
    fn render(
        &mut self,
        state: &TerminalScreen,
        _overlay: &Overlay,
        _status: Option<&str>,
    ) -> std::io::Result<()> {
        *self
            .latest
            .lock()
            .map_err(|e| std::io::Error::other(e.to_string()))? = state.screen().contents();
        Ok(())
    }

    fn size(&self) -> std::io::Result<(u16, u16)> {
        Ok((24, 80))
    }
}

#[test]
fn full_session_over_loopback_pty() {
    runtime().expect("tokio runtime").block_on(async {
        // --- two real iroh endpoints on loopback ---
        let server_ep = bind_endpoint_local(generate_secret_key().expect("OS randomness"), true)
            .await
            .expect("bind server endpoint");
        let client_ep = bind_endpoint_local(generate_secret_key().expect("OS randomness"), false)
            .await
            .expect("bind client endpoint");
        let server_addr = loopback_addr(&server_ep);

        // --- server: accept one connection and run a real PTY shell session ---
        let server_task = tokio::spawn(async move {
            let incoming = server_ep.accept().await.expect("server accept");
            let conn = incoming.await.expect("server handshake");
            // `sh` is portable and quiet; scrollback 0.
            let _ = run_session(
                conn,
                &["sh".to_owned()],
                0,
                koh::pty::Launcher::new(env!("CARGO_BIN_EXE_koh")),
            )
            .await;
        });

        // --- client: connect and run the real session loop against a mock terminal ---
        // A connector for the single connection this test uses. Reconnect is never triggered here:
        // dropping the input sender ends the session via Quit before any link loss.
        let connector = IrohConnector::new(client_ep.clone(), server_addr.clone());
        let conn = client_ep
            .connect(server_addr, ALPN)
            .await
            .expect("client connect over loopback");
        let channel = IrohChannel::new(conn);

        let latest = Arc::new(Mutex::new(String::new()));
        let term = MockTerminal {
            latest: latest.clone(),
        };

        let (input_tx, input_rx) = mpsc::channel::<Vec<u8>>(64);
        // Keep the resize sender alive for the session (never resize here).
        let (resize_tx, resize_rx) = mpsc::channel::<()>(8);

        let client_task = tokio::spawn(async move {
            let _ = run_client(
                channel,
                connector,
                DisplayPreference::Never, // predictions are overlay-only; assert on the real grid
                (24, 80),
                input_rx,
                resize_rx,
                term,
                tokio_util::sync::CancellationToken::new(),
                None,
            )
            .await;
        });

        // Let the shell start and the initial screen sync to the client.
        tokio::time::sleep(Duration::from_millis(700)).await;

        // Type a command with a distinctive marker; the PTY echoes it and `sh` runs it.
        input_tx
            .send(b"echo koh_e2e_marker\r".to_vec())
            .await
            .expect("send keystrokes");

        // Poll the client's rendered screen until the marker round-trips back.
        let mut seen = false;
        for _ in 0..120 {
            if latest.lock().unwrap().contains("koh_e2e_marker") {
                seen = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let final_screen = latest.lock().unwrap().clone();
        assert!(
            seen,
            "marker never round-tripped to the client screen; last frame was:\n{final_screen}"
        );

        // Clean teardown: dropping the input sender ends the client loop, which closes the
        // connection, which ends the server session (and kills the child shell).
        drop(input_tx);
        drop(resize_tx);
        let _ = tokio::time::timeout(Duration::from_secs(3), client_task).await;
        let _ = tokio::time::timeout(Duration::from_secs(3), server_task).await;
    });
}

/// The runtime for a test. `#[tokio::test]` is not used: its expansion `allow`s
/// `clippy::expect_used`, which koh forbids, and a `forbid` rejects that `allow`.
fn runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}
