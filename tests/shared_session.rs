//! Shared sessions over a real loopback iroh connection (KS-01): two distinct peers attached to
//! ONE PTY host see each other's output; a resize from either client reaches the host with its own
//! `ClientId`; the host is reaped only after the last viewer leaves and the TTL elapses.

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

use std::sync::Arc;
use std::time::Duration;

use koh::input::UserInput;
use koh::server::session::{self, HostProvider, PtyHost, SharedHost};
use koh::server::{run_attached, ClientId, SessionExit, SessionHost};
use koh::ssp::Transport;
use koh::terminal::TerminalScreen;
use koh::transport_iroh::{
    bind_endpoint_local, generate_secret_key, loopback_addr, IrohChannel, MonoClock, ALPN,
};
use tokio_util::sync::CancellationToken;

/// Every peer attaches to ONE PTY session (the drain task holds the handle, as in the binary).
fn shared_pty() -> Arc<SharedHost<PtyHost>> {
    Arc::new(SharedHost::new_with_handles(|| {
        session::spawn_session(&["sh".to_owned()], 0)
    }))
}

/// Server accept loop attaching every peer through the shared provider with its own `ClientId`.
fn accept_loop(
    ep: iroh::Endpoint,
    provider: Arc<SharedHost<PtyHost>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(incoming) = ep.accept().await {
            let provider = provider.clone();
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                let peer = conn.remote_id();
                let Ok(Some((h, _))) = provider.attach(peer).await else {
                    return;
                };
                let client = ClientId::next();
                let outcome = run_attached(conn, h.clone(), client).await;
                h.session.lock().await.host.client_detached(client);
                match outcome {
                    Ok(SessionExit::Detached) | Err(_) => provider.detach(peer).await,
                    Ok(SessionExit::ShellExited) => provider.reap(peer).await,
                }
            });
        }
    })
}

/// A client holding ONE koh transport for the life of a connection (as the real client does), so
/// it can send several markers in sequence without confusing the server's established session.
struct TestClient<'a> {
    channel: &'a IrohChannel,
    transport: Transport<UserInput, TerminalScreen>,
    clock: MonoClock,
}

impl<'a> TestClient<'a> {
    fn new(channel: &'a IrohChannel) -> Self {
        let clock = MonoClock::new();
        let mut transport = Transport::<UserInput, TerminalScreen>::new(
            clock.now_ms(),
            channel.max_datagram_size(),
        );
        transport.set_connected(true);
        transport.observe_rtt(10.0);
        Self {
            channel,
            transport,
            clock,
        }
    }

    /// Optionally resize, send `input`, and pump until `marker` is on the screen or `ms` elapse.
    async fn send_and_wait(
        &mut self,
        input: Option<&[u8]>,
        resize: Option<(u16, u16)>,
        marker: &str,
        ms: u64,
    ) -> bool {
        if let Some((r, c)) = resize {
            self.transport.current_mut().push_resize(r, c);
        }
        if let Some(bytes) = input {
            self.transport.current_mut().push_bytes(bytes);
        }
        let deadline = std::time::Instant::now() + Duration::from_millis(ms);
        while std::time::Instant::now() < deadline {
            for dg in self.transport.tick(self.clock.now_ms()) {
                self.channel.send(&dg);
            }
            tokio::select! {
                r = self.channel.recv() => { if let Ok(b) = r { self.transport.recv(self.clock.now_ms(), &b); } }
                () = tokio::time::sleep(Duration::from_millis(5)) => {}
            }
            if self
                .transport
                .remote_state()
                .screen()
                .contents()
                .contains(marker)
            {
                return true;
            }
        }
        false
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_peers_share_one_pty_host() {
    // KS-01: peer A types; peer B, attached to the SAME host, sees it without typing. After B
    // leaves, A still works. After A leaves, the reaper (1 s TTL) tears the host down.
    let server_ep = bind_endpoint_local(generate_secret_key(), true)
        .await
        .expect("bind server");
    let addr = loopback_addr(&server_ep);
    let provider = shared_pty();
    let store = provider.store();
    let accept = accept_loop(server_ep, provider.clone());

    let ep_a = bind_endpoint_local(generate_secret_key(), false)
        .await
        .expect("bind A");
    let ep_b = bind_endpoint_local(generate_secret_key(), false)
        .await
        .expect("bind B");

    let chan_a = IrohChannel::new(ep_a.connect(addr.clone(), ALPN).await.expect("A connect"));
    let chan_b = IrohChannel::new(ep_b.connect(addr.clone(), ALPN).await.expect("B connect"));
    let mut client_a = TestClient::new(&chan_a);
    let mut client_b = TestClient::new(&chan_b);
    assert!(
        client_a
            .send_and_wait(
                Some(b"echo SHARED_MARKER_1\r"),
                None,
                "SHARED_MARKER_1",
                10_000
            )
            .await,
        "A sees its own marker"
    );
    // KS-03: B's loop is woken by the same pulse as A's, so B sees the marker promptly. With the
    // old single-waiter notify, B re-rendered only on its 1 s timer cap.
    let started = std::time::Instant::now();
    assert!(
        client_b
            .send_and_wait(None, None, "SHARED_MARKER_1", 10_000)
            .await,
        "B, on the same host, sees A's marker without typing"
    );
    let lag = started.elapsed();
    assert!(
        lag < Duration::from_millis(500),
        "B saw A's marker {lag:?} after A did; every viewer must wake on a change (KS-03)"
    );
    let handle = store
        .lock()
        .await
        .values()
        .next()
        .cloned()
        .expect("one shared entry");
    assert_eq!(
        store.lock().await.len(),
        1,
        "a shared host is one store entry"
    );
    assert_eq!(
        handle.session.lock().await.attached,
        2,
        "both peers are attached to the one session"
    );

    drop(client_b);
    chan_b.close(0, b"B leaves");
    drop(chan_b);
    // Keep A alive while B's detach propagates on the server.
    for _ in 0..20 {
        if handle.session.lock().await.attached == 1 {
            break;
        }
        let _ = client_a.send_and_wait(None, None, "\u{0}never", 100).await;
    }
    assert_eq!(
        handle.session.lock().await.attached,
        1,
        "only A remains attached"
    );
    assert!(
        handle.session.lock().await.last_detach.is_none(),
        "A is still attached: the detach timer must not arm"
    );
    assert!(
        client_a
            .send_and_wait(
                Some(b"echo SHARED_MARKER_2\r"),
                None,
                "SHARED_MARKER_2",
                10_000
            )
            .await,
        "A keeps working after B detached"
    );

    drop(client_a);
    chan_a.close(0, b"A leaves");
    drop(chan_a);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        handle.session.lock().await.last_detach.is_some(),
        "last viewer gone: the detach timer arms"
    );

    // 1 s TTL, 50 ms sweeps: the host is reaped from the store.
    let shutdown = CancellationToken::new();
    let reaper = tokio::spawn(session::run_reaper(
        store.clone(),
        Duration::from_secs(1),
        Duration::from_millis(50),
        shutdown.clone(),
    ));
    let mut reaped = false;
    for _ in 0..100 {
        if store.lock().await.is_empty() {
            reaped = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), reaper).await;
    assert!(reaped, "after the TTL the shared host is torn down");
    accept.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn second_viewer_gets_its_own_echo_ack() {
    // KS-02: echo-ack is per connection. A types 30 separate frames; then B types one. B's replica
    // must be acked for its own frame and must never observe an ack above its own newest sent
    // frame — a host-global ack would hand B A's frame number (~30) immediately.
    let server_ep = bind_endpoint_local(generate_secret_key(), true)
        .await
        .expect("bind server");
    let addr = loopback_addr(&server_ep);
    let provider = shared_pty();
    let accept = accept_loop(server_ep, provider.clone());

    let ep_a = bind_endpoint_local(generate_secret_key(), false)
        .await
        .expect("bind A");
    let ep_b = bind_endpoint_local(generate_secret_key(), false)
        .await
        .expect("bind B");
    let chan_a = IrohChannel::new(ep_a.connect(addr.clone(), ALPN).await.expect("A connect"));
    let chan_b = IrohChannel::new(ep_b.connect(addr, ALPN).await.expect("B connect"));
    let mut client_a = TestClient::new(&chan_a);
    let mut client_b = TestClient::new(&chan_b);
    assert!(
        client_a
            .send_and_wait(Some(b"echo ECHO_A\r"), None, "ECHO_A", 10_000)
            .await
    );
    for _ in 0..30 {
        // One byte per frame; a space is harmless at the prompt. Each pump lets the frame ship.
        let _ = client_a
            .send_and_wait(Some(b" "), None, "\u{0}never", 40)
            .await;
        let (ack, sent) = (
            client_b.transport.remote_state().echo_ack(),
            client_b.transport.newest_sent_num(),
        );
        assert!(
            ack <= sent,
            "B acked above its own frames: ack {ack} > sent {sent}"
        );
    }
    // Let A's acks drain. 30 pushes at 40 ms are well over 10 frames even if the transport's
    // send interval coalesces some of them.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut a_ack = 0;
    while std::time::Instant::now() < deadline && a_ack < 10 {
        let _ = client_a.send_and_wait(None, None, "\u{0}never", 50).await;
        a_ack = client_a.transport.remote_state().echo_ack();
    }
    assert!(a_ack >= 10, "A's own frames are acked to A: {a_ack}");

    assert!(
        client_b
            .send_and_wait(Some(b"echo ECHO_B\r"), None, "ECHO_B", 10_000)
            .await
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut b_ack = 0;
    while std::time::Instant::now() < deadline {
        let _ = client_b.send_and_wait(None, None, "\u{0}never", 50).await;
        b_ack = client_b.transport.remote_state().echo_ack();
        let sent = client_b.transport.newest_sent_num();
        assert!(
            b_ack <= sent,
            "B acked above its own frames: ack {b_ack} > sent {sent}"
        );
        if b_ack >= 1 {
            break;
        }
    }
    assert!(
        b_ack >= 1 && b_ack < a_ack,
        "B is acked for its own frame ({b_ack}), not A's ({a_ack})"
    );

    chan_a.close(0, b"done");
    chan_b.close(0, b"done");
    accept.abort();
    let store = provider.store();
    let handle = store.lock().await.values().next().cloned();
    if let Some(h) = handle {
        let _ = h.session.lock().await.host.pty.kill();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resize_from_either_client_reaches_the_host_and_the_last_one_wins() {
    // KS-01: two viewers with different geometries; the host applies each resize as it arrives
    // (last wins for v1), so the emulator ends at the second client's size.
    let server_ep = bind_endpoint_local(generate_secret_key(), true)
        .await
        .expect("bind server");
    let addr = loopback_addr(&server_ep);
    let provider = shared_pty();
    let store = provider.store();
    let accept = accept_loop(server_ep, provider.clone());

    let ep_a = bind_endpoint_local(generate_secret_key(), false)
        .await
        .expect("bind A");
    let chan_a = IrohChannel::new(ep_a.connect(addr.clone(), ALPN).await.expect("A connect"));
    let mut client_a = TestClient::new(&chan_a);
    assert!(
        client_a
            .send_and_wait(
                Some(b"echo RESIZE_A\r"),
                Some((40, 120)),
                "RESIZE_A",
                10_000
            )
            .await
    );
    let handle = store
        .lock()
        .await
        .values()
        .next()
        .cloned()
        .expect("one shared entry");
    assert_eq!(
        handle.session.lock().await.host.snapshot().size(),
        (40, 120),
        "A's geometry applied"
    );

    let ep_b = bind_endpoint_local(generate_secret_key(), false)
        .await
        .expect("bind B");
    let chan_b = IrohChannel::new(ep_b.connect(addr, ALPN).await.expect("B connect"));
    let mut client_b = TestClient::new(&chan_b);
    assert!(
        client_b
            .send_and_wait(Some(b"echo RESIZE_B\r"), Some((20, 60)), "RESIZE_B", 10_000)
            .await
    );
    assert_eq!(
        handle.session.lock().await.host.snapshot().size(),
        (20, 60),
        "B's later geometry wins"
    );

    chan_a.close(0, b"done");
    chan_b.close(0, b"done");
    accept.abort();
    let _ = handle.session.lock().await.host.pty.kill();
}
