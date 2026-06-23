//! End-to-end: two `ssp::Transport`s synchronizing over a **real iroh datagram connection**.
//!
//! The unit tests cover endpoint/identity/channel plumbing and the SSP convergence is proven
//! deterministically by `ssp::testkit` over a simulated link. This test closes the gap between
//! them: it runs the actual SSP send/recv loop across genuine QUIC datagrams (loopback, no
//! relay), asserting the receiver converges to the sender's state.

// Integration test: every `unwrap`/`expect`/panic here IS the test's assertion of success.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "integration test code; a failed unwrap/expect is the test failing"
)]

use std::time::Duration;

use koh::ssp::{SyncState, Transport};
use koh::transport_iroh::{
    bind_endpoint_local, generate_secret_key, loopback_addr, IrohChannel, ALPN,
};
use serde::{Deserialize, Serialize};

/// A growing byte-log state (no collapse), so the receiver's view equals the sender's exactly.
#[derive(Clone, Default, PartialEq, Debug)]
struct Log(Vec<u8>);

#[derive(Serialize, Deserialize, Clone)]
struct LogDiff(Vec<u8>);

impl SyncState for Log {
    type Diff = LogDiff;
    fn diff_from(&self, base: &Self) -> LogDiff {
        let n = base.0.len().min(self.0.len());
        LogDiff(self.0[n..].to_vec())
    }
    fn apply(&mut self, d: &LogDiff) {
        self.0.extend_from_slice(&d.0);
    }
}

#[tokio::test]
async fn ssp_transports_converge_over_real_iroh() {
    // --- a real loopback iroh connection ---
    let server = bind_endpoint_local(generate_secret_key(), true)
        .await
        .expect("bind server");
    let client = bind_endpoint_local(generate_secret_key(), false)
        .await
        .expect("bind client");
    let server_addr = loopback_addr(&server);

    let server_ep = server.clone();
    let accept = tokio::spawn(async move {
        server_ep
            .accept()
            .await
            .expect("accept")
            .await
            .expect("handshake")
    });
    let client_conn = client.connect(server_addr, ALPN).await.expect("connect");
    let server_conn = accept.await.expect("accept join");

    let chan_a = IrohChannel::new(client_conn); // side A
    let chan_b = IrohChannel::new(server_conn); // side B
    let mtu = chan_a.max_datagram_size();

    let mut ta = Transport::<Log, Log>::new(0, mtu);
    let mut tb = Transport::<Log, Log>::new(0, mtu);
    ta.set_connected(true);
    tb.set_connected(true);
    // Loopback RTT is ~0; feed a small sample so the send interval drops to its floor.
    ta.observe_rtt(10.0);
    tb.observe_rtt(10.0);

    // A authors data; B must converge to it across real datagrams.
    let payload = b"hello over real iroh datagrams \xf0\x9f\xa6\x80".to_vec();
    ta.current_mut().0.extend_from_slice(&payload);

    let start = tokio::time::Instant::now();
    let now = || start.elapsed().as_millis() as u64;

    loop {
        for dg in ta.tick(now()) {
            chan_a.send(&dg);
        }
        for dg in tb.tick(now()) {
            chan_b.send(&dg);
        }

        tokio::select! {
            r = chan_a.recv() => { if let Ok(bytes) = r { ta.recv(now(), &bytes); } }
            r = chan_b.recv() => { if let Ok(bytes) = r { tb.recv(now(), &bytes); } }
            _ = tokio::time::sleep(Duration::from_millis(5)) => {}
        }

        if tb.remote_state().0 == payload {
            break;
        }
        assert!(
            now() < 15_000,
            "SSP did not converge over real iroh in time"
        );
    }

    assert_eq!(
        tb.remote_state().0,
        payload,
        "B converged to A's state over real iroh"
    );

    chan_a.close(0, b"done");
    drop((server, client));
}
