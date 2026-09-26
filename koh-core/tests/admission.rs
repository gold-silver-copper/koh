//! The connection-admission barrier (`transport_iroh::admission`): a server that admits a peer
//! unblocks the client's `await_admission`; a server that rejects (closes without admitting) makes
//! `await_admission` return an error, so a rejected client fails fast instead of re-dialing forever.
//! Hermetic loopback iroh connections.

use std::time::Duration;

use koh_core::transport_iroh::admission::{admit, await_admission};
use koh_core::transport_iroh::{bind_endpoint_local, generate_secret_key, loopback_addr, ALPN};

#[test]
fn admit_unblocks_await_admission() {
    runtime().expect("tokio runtime").block_on(async {
        let server = bind_endpoint_local(generate_secret_key().expect("OS randomness"), true)
            .await
            .expect("bind server");
        let client = bind_endpoint_local(generate_secret_key().expect("OS randomness"), false)
            .await
            .expect("bind client");
        let addr = loopback_addr(&server);

        let server_ep = server.clone();
        let accept = tokio::spawn(async move {
            let incoming = server_ep.accept().await.expect("incoming");
            let conn = incoming.await.expect("accept conn");
            admit(&conn).await.expect("admit");
            // Hold the connection briefly so the client's accept_bi sees the stream.
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        let conn = client.connect(addr, ALPN).await.expect("connect");
        await_admission(&conn)
            .await
            .expect("client must be admitted");
        accept.await.expect("accept task");
    });
}

#[test]
fn reject_surfaces_as_error() {
    runtime().expect("tokio runtime").block_on(async {
        let server = bind_endpoint_local(generate_secret_key().expect("OS randomness"), true)
            .await
            .expect("bind server");
        let client = bind_endpoint_local(generate_secret_key().expect("OS randomness"), false)
            .await
            .expect("bind client");
        let addr = loopback_addr(&server);

        let server_ep = server.clone();
        let accept = tokio::spawn(async move {
            let incoming = server_ep.accept().await.expect("incoming");
            let conn = incoming.await.expect("accept conn");
            // Reject: close WITHOUT opening the admission stream (mirrors the not-on-allowlist path).
            conn.close(1u32.into(), b"not authorized");
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        let conn = client.connect(addr, ALPN).await.expect("connect");
        assert!(
            await_admission(&conn).await.is_err(),
            "a server that closes without admitting must surface as not-admitted (not hang)"
        );
        accept.await.expect("accept task");
    });
}

/// The runtime for a test. `#[tokio::test]` is not used: its expansion `allow`s
/// `clippy::expect_used`, which koh-core forbids, and a `forbid` rejects that `allow`.
fn runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
}
