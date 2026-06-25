//! End-to-end verification of the `--read-only` gate over the real `run_attached` data path
//! (loopback iroh connections, mirroring `reattach.rs`'s harness):
//!   * a read-only session must DROP the client's keystrokes — they never reach the shell —
//!   * with a read-write positive control proving the harness *can* deliver input quickly, so the
//!     negative isn't a false pass from a dead connection.

// Integration test: a failed unwrap/expect/assert IS the test failing.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::default_trait_access,
    reason = "integration test code; panics are assertion failures"
)]
use std::time::Duration;

use iroh::endpoint::Endpoint;
use koh::input::UserInput;
use koh::server::session::{self, SessionStore};
use koh::server::{run_attached, SessionExit};
use koh::ssp::Transport;
use koh::terminal::TerminalScreen;
use koh::transport_iroh::{
    bind_endpoint_local, generate_secret_key, loopback_addr, IrohChannel, MonoClock, ALPN,
};

/// Pump a fresh client transport: optionally type `input`, then watch the *synced server screen*
/// (the confirmed remote state, NOT the local prediction overlay) for `marker`. Returns whether it
/// appeared within `ms`.
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

/// Spawn an accept loop that attaches every peer with the given `read_only` setting, then serves it.
fn serve_readonly(
    ep: Endpoint,
    store: SessionStore,
    read_only: bool,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(incoming) = ep.accept().await {
            let store = store.clone();
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                let peer = conn.remote_id();
                let Ok(Some((handle, _))) =
                    session::attach(&store, peer, Some("sh"), 0, 64, read_only).await
                else {
                    return;
                };
                match run_attached(conn, handle).await {
                    Ok(SessionExit::Detached) | Err(_) => session::detach(&store, peer).await,
                    Ok(SessionExit::ShellExited) => session::reap(&store, peer).await,
                }
            });
        }
    })
}

/// Bind a fresh (server, client) endpoint pair on loopback + the server's dial address.
async fn endpoints() -> (Endpoint, Endpoint, iroh::EndpointAddr) {
    let server = bind_endpoint_local(generate_secret_key(), true)
        .await
        .expect("bind server");
    let client = bind_endpoint_local(generate_secret_key(), false)
        .await
        .expect("bind client");
    let addr = loopback_addr(&server);
    (server, client, addr)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn read_only_drops_client_input() {
    let (server, client, addr) = endpoints().await;
    let store: SessionStore = Default::default();
    let accept = serve_readonly(server.clone(), store.clone(), /* read_only */ true);

    let conn = client.connect(addr, ALPN).await.expect("connect");
    let chan = IrohChannel::new(conn);
    // The marker can only appear if the shell ran (or even just echoed) the typed line. In a
    // read-only session the keystrokes are dropped before the PTY, so it must never show up.
    let appeared = client_pump(&chan, Some(b"echo RO_DENIED_7\r"), "RO_DENIED_7", 4_000).await;
    assert!(
        !appeared,
        "a read-only (restrict) session must DROP client input — the marker must never appear"
    );
    chan.close(0, b"done");
    accept.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn read_write_delivers_client_input() {
    // Positive control for the test above: the SAME harness with read_only=false MUST deliver the
    // keystrokes (typically sub-second), proving the negative isn't a false pass from a dead link.
    let (server, client, addr) = endpoints().await;
    let store: SessionStore = Default::default();
    let accept = serve_readonly(server.clone(), store.clone(), /* read_only */ false);

    let conn = client.connect(addr, ALPN).await.expect("connect");
    let chan = IrohChannel::new(conn);
    let appeared = client_pump(&chan, Some(b"echo RW_OK_7\r"), "RW_OK_7", 10_000).await;
    assert!(
        appeared,
        "a read-write session must deliver the client's keystrokes to the shell"
    );
    chan.close(0, b"done");
    accept.abort();
}
