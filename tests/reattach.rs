//! P0 acceptance: a detached session survives the client disconnecting and is re-attached, at
//! the *current* screen, when the same client reconnects — mosh's "close the laptop, reopen,
//! it's right where you left it." Hermetic: two loopback iroh connections from one client
//! endpoint (so the peer id — the session key — is stable across reconnects).

// Integration test: a failed unwrap/expect/assert IS the test failing.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::items_after_statements,
    clippy::default_trait_access,
    reason = "integration test code; panics are assertion failures"
)]
use std::time::Duration;

use koh::input::UserInput;
use koh::server::session::{self, SessionStore};
use koh::server::{run_attached, SessionExit};
use koh::ssp::Transport;
use koh::terminal::TerminalScreen;
use koh::transport_iroh::{
    bind_endpoint_local, generate_secret_key, loopback_addr, IrohChannel, MonoClock, ALPN,
};

/// Drive a *fresh* client-side transport over `channel`: optionally type `input`, then pump
/// until the rendered screen contains `marker` (or time out). Mirrors the real client's loop
/// closely enough to exercise the server's attach/re-sync path.
async fn client_pump(channel: &IrohChannel, input: Option<&[u8]>, marker: &str, ms: u64) -> bool {
    let clock = MonoClock::new();
    let mut t =
        Transport::<UserInput, TerminalScreen>::new(clock.now_ms(), channel.max_datagram_size());
    t.set_connected(true);
    t.observe_rtt(10.0);
    if let Some(inp) = input {
        t.current_mut().push_bytes(inp);
    }
    let start = tokio::time::Instant::now();
    loop {
        let now = clock.now_ms();
        for dg in t.tick(now) {
            channel.send(&dg);
        }
        tokio::select! {
            r = channel.recv() => { if let Ok(bytes) = r { t.recv(now, &bytes); } }
            _ = tokio::time::sleep(Duration::from_millis(5)) => {}
        }
        if t.remote_state().screen().contents().contains(marker) {
            return true;
        }
        if start.elapsed() > Duration::from_millis(ms) {
            return false;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_survives_disconnect_and_reattaches() {
    let server_ep = bind_endpoint_local(generate_secret_key(), true)
        .await
        .expect("bind server");
    // One client endpoint, reused for both connects -> stable peer id (the session key).
    let client_ep = bind_endpoint_local(generate_secret_key(), false)
        .await
        .expect("bind client");
    let server_addr = loopback_addr(&server_ep);

    // Server accept loop with a session store (no reaper: keep sessions for the test's life).
    let store: SessionStore = Default::default();
    let accept_ep = server_ep.clone();
    let accept_store = store.clone();
    let accept = tokio::spawn(async move {
        while let Some(incoming) = accept_ep.accept().await {
            let store = accept_store.clone();
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                let peer = conn.remote_id();
                let Ok(Some((handle, _))) =
                    session::attach(&store, peer, Some("sh"), None, 0, 64).await
                else {
                    return;
                };
                match run_attached(conn, handle).await {
                    Ok(SessionExit::Detached) | Err(_) => session::detach(&store, peer).await,
                    Ok(SessionExit::ShellExited) => session::reap(&store, peer).await,
                }
            });
        }
    });

    const MARKER: &str = "REATTACH_MARKER_42";

    // --- connection #1: type a command, confirm it round-tripped onto the screen ---
    let conn1 = client_ep
        .connect(server_addr.clone(), ALPN)
        .await
        .expect("connect #1");
    let chan1 = IrohChannel::new(conn1);
    let saw1 = client_pump(&chan1, Some(b"echo REATTACH_MARKER_42\r"), MARKER, 10_000).await;
    assert!(
        saw1,
        "marker should appear on the screen during the first connection"
    );

    // Disconnect (the shell keeps running in the detached session).
    chan1.close(0, b"client detached");
    drop(chan1);
    tokio::time::sleep(Duration::from_millis(500)).await; // let the server detach

    // --- connection #2 from the SAME client endpoint: must re-sync to the persisted screen ---
    let conn2 = client_ep
        .connect(server_addr, ALPN)
        .await
        .expect("connect #2");
    let chan2 = IrohChannel::new(conn2);
    // No input this time: a fresh transport must re-sync to the current (persisted) screen.
    let saw2 = client_pump(&chan2, None, MARKER, 10_000).await;
    assert!(
        saw2,
        "after reconnecting, the client must re-sync to the SAME session showing the marker"
    );

    chan2.close(0, b"done");
    accept.abort();
}
