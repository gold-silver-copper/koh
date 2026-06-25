//! Ported mosh integration tests, recast hermetically over loopback iroh:
//! - `xon_xoff_cycle_does_not_wedge_session`  ← mosh src/tests/pty-deadlock.test
//! - `session_lifecycle_stress`               ← mosh src/tests/repeat.test
//! - `session_lifecycle_stress_with_input`    ← mosh src/tests/repeat-with-input.test
//! - `window_resize_propagates_to_shell`      ← mosh src/tests/window-resize.test
//!
//! Each drives a fresh client-side `Transport` against a real loopback session (a PTY-hosted
//! `sh`), exactly like the real client's loop, so the full input → PTY → emulator → diff → client
//! path is exercised without a TTY or a second machine.

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

use iroh::endpoint::Endpoint;
use iroh::EndpointAddr;
use koh::input::UserInput;
use koh::server::session::{self, SessionStore};
use koh::server::{run_attached, SessionExit};
use koh::ssp::Transport;
use koh::terminal::TerminalScreen;
use koh::transport_iroh::{
    bind_endpoint_local, generate_secret_key, loopback_addr, IrohChannel, MonoClock, ALPN,
};

/// A running loopback server: endpoint, its dial address, the session store, and the accept task.
type RunningServer = (
    Endpoint,
    EndpointAddr,
    SessionStore,
    tokio::task::JoinHandle<()>,
);

/// Start a loopback server with a session store and an accept loop that attaches each connection
/// to its peer's detachable session (mirrors the real `koh-server` accept loop).
async fn start_server() -> RunningServer {
    let server_ep = bind_endpoint_local(generate_secret_key(), true)
        .await
        .expect("bind server");
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
                let Ok(Some((handle, _))) =
                    session::attach(&store, peer, Some("sh"), 0, 64, false).await
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
    (server_ep, server_addr, store, accept)
}

/// One scripted client action: an optional resize to `(rows, cols)`, plus input bytes to send.
type Step<'a> = (Option<(u16, u16)>, &'a [u8]);

/// Drive a fresh client transport over `channel`: run each step in order, then pump until the
/// rendered screen contains `marker` (or time out). A step may push a resize, some input bytes, or
/// both; steps are applied to consecutive frames so the server sees them in order.
async fn client_script(channel: &IrohChannel, steps: &[Step<'_>], marker: &str, ms: u64) -> bool {
    let clock = MonoClock::new();
    let mut t =
        Transport::<UserInput, TerminalScreen>::new(clock.now_ms(), channel.max_datagram_size());
    t.set_connected(true);
    t.observe_rtt(10.0);
    for (resize, keys) in steps {
        if let Some((rows, cols)) = resize {
            t.current_mut().push_resize(*rows, *cols);
        }
        if !keys.is_empty() {
            t.current_mut().push_bytes(keys);
        }
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
async fn xon_xoff_cycle_does_not_wedge_session() {
    // mosh pty-deadlock.test: on BSD, a ^S written to the pty master between select() and read()
    // could wedge the whole session. koh's PTY reader is a dedicated blocking thread (no
    // select+read race), so it is structurally immune to that specific deadlock; this guards the
    // observable contract — a ^S (XOFF) / ^Q (XON) cycle in the input stream must not break the
    // session, and output after it must still flow.
    let (_server, addr, _store, accept) = start_server().await;
    let client_ep = bind_endpoint_local(generate_secret_key(), false)
        .await
        .expect("bind client");
    let chan = IrohChannel::new(client_ep.connect(addr, ALPN).await.expect("connect"));

    // First marker proves the session is live; then ^S, ^Q, and a second command that must arrive.
    let ok = client_script(
        &chan,
        &[
            (None, b"echo MOSH_XON_1\r"),
            (None, b"\x13\x11echo MOSH_XON_2\r"), // ^S then ^Q, then a command
        ],
        "MOSH_XON_2",
        15_000,
    )
    .await;
    assert!(
        ok,
        "session must keep delivering output across a ^S/^Q cycle (no wedge)"
    );

    chan.close(0, b"done");
    accept.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_lifecycle_stress() {
    // mosh repeat.test: run a session many times in succession; a leak or teardown race shows up
    // as a hang or failure on some iteration. Here: reconnect the SAME client (so it reattaches
    // its detachable session) many times, each time round-tripping a fresh marker.
    let (_server, addr, _store, accept) = start_server().await;
    let client_ep = bind_endpoint_local(generate_secret_key(), false)
        .await
        .expect("bind client");

    const ITERS: usize = 20;
    for i in 0..ITERS {
        let chan = IrohChannel::new(
            client_ep
                .connect(addr.clone(), ALPN)
                .await
                .unwrap_or_else(|e| panic!("iteration {i}: connect failed: {e}")),
        );
        let marker = format!("MOSH_REPEAT_{i}");
        let ok = client_script(
            &chan,
            &[(None, format!("echo {marker}\r").as_bytes())],
            &marker,
            10_000,
        )
        .await;
        assert!(ok, "iteration {i}: marker {marker} must round-trip");
        chan.close(0, b"next");
        drop(chan);
    }

    accept.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_lifecycle_stress_with_input() {
    // mosh repeat-with-input.test: like repeat, but constantly send input — exercises the race
    // where input arriving as/after a connection tears down used to crash the server. Each
    // iteration sends a burst of CRs, confirms a marker, then drops the connection abruptly.
    let (_server, addr, _store, accept) = start_server().await;
    let client_ep = bind_endpoint_local(generate_secret_key(), false)
        .await
        .expect("bind client");

    const ITERS: usize = 15;
    for i in 0..ITERS {
        let chan = IrohChannel::new(
            client_ep
                .connect(addr.clone(), ALPN)
                .await
                .unwrap_or_else(|e| panic!("iteration {i}: connect failed: {e}")),
        );
        let marker = format!("MOSH_RWI_{i}");
        // A burst of bare CRs (newlines at the shell), then the marker command.
        let ok = client_script(
            &chan,
            &[
                (None, b"\r\r\r\r\r"),
                (None, format!("echo {marker}\r").as_bytes()),
            ],
            &marker,
            10_000,
        )
        .await;
        assert!(
            ok,
            "iteration {i}: marker {marker} must round-trip under input spam"
        );
        // Abrupt drop (no graceful close) to exercise teardown-with-pending-input.
        drop(chan);
    }

    accept.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn window_resize_propagates_to_shell() {
    // mosh window-resize.test: a window-size change must reach the shell (SIGWINCH + new winsize),
    // so a full-screen app redraws. Here: resize the session to 30x100 via the input stream, then
    // run `stty size` — the shell must report the new geometry.
    let (_server, addr, _store, accept) = start_server().await;
    let client_ep = bind_endpoint_local(generate_secret_key(), false)
        .await
        .expect("bind client");
    let chan = IrohChannel::new(client_ep.connect(addr, ALPN).await.expect("connect"));

    let ok = client_script(
        &chan,
        &[(Some((30, 100)), b"stty size\r")],
        "30 100",
        10_000,
    )
    .await;
    assert!(
        ok,
        "after resizing to 30x100, `stty size` in the shell must report the new geometry"
    );

    chan.close(0, b"done");
    accept.abort();
}
