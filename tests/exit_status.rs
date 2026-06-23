//! P2 acceptance: when the remote shell exits with a status code, that code rides the shutdown
//! frame to the client so the client binary can exit with it (mosh propagates `$?`). Hermetic:
//! a loopback session where `sh` runs `exit 42`, driven by a client-side transport that pumps
//! until the shutdown sentinel and then reads the exit code off the synced state.

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
use koh::ssp::{Transport, SHUTDOWN_SENTINEL};
use koh::terminal::TerminalScreen;
use koh::transport_iroh::{
    bind_endpoint_local, generate_secret_key, loopback_addr, IrohChannel, MonoClock, ALPN,
};

/// Drive a fresh client transport: type `input`, then pump until the server announces shutdown
/// (`remote_num == SHUTDOWN_SENTINEL`) and return the propagated exit code, or `None` on timeout.
async fn pump_until_exit(channel: &IrohChannel, input: &[u8], ms: u64) -> Option<Option<u32>> {
    let clock = MonoClock::new();
    let mut t =
        Transport::<UserInput, TerminalScreen>::new(clock.now_ms(), channel.max_datagram_size());
    t.set_connected(true);
    t.observe_rtt(10.0);
    t.current_mut().push_bytes(input);
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
        if t.remote_num() == SHUTDOWN_SENTINEL {
            return Some(t.remote_state().exit_code());
        }
        if start.elapsed() > Duration::from_millis(ms) {
            return None;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remote_shell_exit_status_reaches_client() {
    let server_ep = bind_endpoint_local(generate_secret_key(), true)
        .await
        .expect("bind server");
    let client_ep = bind_endpoint_local(generate_secret_key(), false)
        .await
        .expect("bind client");
    let server_addr = loopback_addr(&server_ep);

    let store: SessionStore = Default::default();
    let accept_ep = server_ep.clone();
    let accept_store = store.clone();
    let accept = tokio::spawn(async move {
        while let Some(incoming) = accept_ep.accept().await {
            let store = accept_store.clone();
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                let peer = conn.remote_id();
                let Ok(Some((handle, _))) = session::attach(&store, peer, Some("sh"), 0, 64).await
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

    let conn = client_ep.connect(server_addr, ALPN).await.expect("connect");
    let chan = IrohChannel::new(conn);

    // `sh` runs `exit 42`; the shell terminates, the drain task reaps the real status and stamps
    // it onto the emulator, and the shutdown handshake carries it to us.
    let code = pump_until_exit(&chan, b"exit 42\r", 10_000).await;
    assert_eq!(
        code,
        Some(Some(42)),
        "client must observe the remote shell's exit code (42) on the shutdown frame"
    );

    chan.close(0, b"done");
    accept.abort();
}
