//! Tier 1 end-to-end: the client **transparently reconnects and reattaches** after the link drops.
//!
//! This is the regression test for the "phone screen-off → koh exits to the shell" bug. It runs
//! the real client session loop ([`run_client`]) against a real PTY-hosted shell over loopback
//! iroh, forcibly **closes the connection mid-session while keeping the server session alive**
//! (exactly what a QUIC idle-timeout does when Android freezes the process), and asserts that the
//! client re-dials, reattaches to the **same** shell, and keeps working — rather than returning.
//!
//! The decisive assertion is that the first command's output is **still on screen** after the
//! reconnect (proving the same shell, not a freshly-spawned one) while a second command, typed
//! only after the drop, also runs.

// Integration test: a failed unwrap/expect/assert IS the test failing.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::unwrap_in_result,
    reason = "integration test code; panics are assertion failures"
)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use koh_client::{run_client, ClientTerminal, IrohConnector};
use koh_predict::{DisplayPreference, Overlay};
use koh_server::session::spawn_session;
use koh_server::{run_attached, SessionExit};
use koh_transport_iroh::{bind_endpoint_local, generate_secret_key, loopback_addr, IrohChannel};
use tokio::sync::{mpsc, oneshot};

/// Captures the latest authoritative screen as text, so the test can assert on what the user sees.
struct MockTerminal {
    latest: Arc<Mutex<String>>,
}

impl ClientTerminal for MockTerminal {
    fn render(
        &mut self,
        screen: &vt100::Screen,
        _overlay: &Overlay,
        _status: Option<&str>,
    ) -> std::io::Result<()> {
        *self.latest.lock().unwrap() = screen.contents();
        Ok(())
    }

    fn size(&self) -> std::io::Result<(u16, u16)> {
        Ok((24, 80))
    }
}

/// Poll `latest` until it contains `needle`, up to `tries` × 100ms. Returns whether it appeared.
async fn wait_for(latest: &Arc<Mutex<String>>, needle: &str, tries: u32) -> bool {
    for _ in 0..tries {
        if latest.lock().unwrap().contains(needle) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

#[tokio::test]
async fn client_reconnects_and_reattaches_after_a_forced_drop() {
    // --- two real iroh endpoints on loopback ---
    let server_ep = bind_endpoint_local(generate_secret_key(), true)
        .await
        .expect("bind server endpoint");
    let client_ep = bind_endpoint_local(generate_secret_key(), false)
        .await
        .expect("bind client endpoint");
    let server_addr = loopback_addr(&server_ep);

    // The test signals this once MARK_ONE has round-tripped, to force-close connection #1.
    let (kill_tx, kill_rx) = oneshot::channel::<()>();

    // --- server: ONE detachable session, accepted over a loop so a reconnect reattaches it ---
    let server_task = tokio::spawn(async move {
        let handle = spawn_session(Some("sh"), 0).expect("spawn session");
        let mut arm_kill = Some(kill_rx);
        loop {
            let Some(incoming) = server_ep.accept().await else {
                break;
            };
            let Ok(conn) = incoming.await else {
                continue;
            };
            // For the FIRST connection only, force-close it when the test says so — WITHOUT
            // killing the shell. This is exactly what a QUIC idle-timeout does when the phone
            // freezes the client: the connection dies but the server session lives on.
            if let Some(krx) = arm_kill.take() {
                let victim = conn.clone();
                tokio::spawn(async move {
                    if krx.await.is_ok() {
                        IrohChannel::new(victim).close(0, b"simulated idle timeout");
                    }
                });
            }
            // Every connection completes the (no-passphrase) auth handshake, exactly like the real
            // server — the client's connector always runs the client half, so this must answer it.
            if koh_transport_iroh::auth::handshake_server(&conn, None)
                .await
                .is_err()
            {
                continue;
            }
            match run_attached(conn, handle.clone()).await {
                Ok(SessionExit::Detached) => {} // reattach on the next accept
                _ => break,                     // shell exited (or error)
            }
        }
    });

    // --- client: the reconnecting session loop against a capturing mock terminal ---
    // The connector does the initial dial + handshake (and every reconnect), just like the binary.
    let connector = IrohConnector::new(client_ep.clone(), server_addr.clone(), Arc::new(None));
    let channel = connector
        .connect()
        .await
        .expect("client connect over loopback");

    let latest = Arc::new(Mutex::new(String::new()));
    let term = MockTerminal {
        latest: latest.clone(),
    };
    let (input_tx, input_rx) = mpsc::channel::<Vec<u8>>(64);
    let (resize_tx, resize_rx) = mpsc::channel::<()>(8);

    let client_task = tokio::spawn(async move {
        let _ = run_client(
            channel,
            connector,
            DisplayPreference::Never,
            (24, 80),
            input_rx,
            resize_rx,
            term,
        )
        .await;
    });

    // Let the shell come up and the first screen sync.
    tokio::time::sleep(Duration::from_millis(700)).await;

    // First command: prove the session works before the drop.
    input_tx
        .send(b"echo MARK_ONE\r".to_vec())
        .await
        .expect("send marker one");
    assert!(
        wait_for(&latest, "MARK_ONE", 120).await,
        "first command never round-tripped; screen was:\n{}",
        latest.lock().unwrap()
    );

    // Force the disconnect (the screen-off idle-timeout). The shell keeps running server-side.
    kill_tx.send(()).expect("trigger forced disconnect");

    // The client should now re-dial and reattach. Bytes typed *during* the reconnect are dropped
    // (the reconnect loop only watches for the quit escape), so re-send the second command until
    // it lands once the session is live again.
    let mut seen_two = false;
    for _ in 0..150 {
        let _ = input_tx.send(b"echo MARK_TWO\r".to_vec()).await;
        if latest.lock().unwrap().contains("MARK_TWO") {
            seen_two = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    let final_screen = latest.lock().unwrap().clone();
    assert!(
        seen_two,
        "second command never ran after reconnect; screen was:\n{final_screen}"
    );
    // The decisive check: the SAME shell resumed — MARK_ONE's output survived the reconnect.
    // A freshly-spawned shell would have an empty scrollback and no MARK_ONE.
    assert!(
        final_screen.contains("MARK_ONE"),
        "reconnect must reattach the SAME shell (MARK_ONE history preserved); screen was:\n{final_screen}"
    );

    // Teardown: dropping the input sender ends the client loop; abort the server's accept loop.
    drop(input_tx);
    drop(resize_tx);
    let _ = tokio::time::timeout(Duration::from_secs(3), client_task).await;
    server_task.abort();
}
