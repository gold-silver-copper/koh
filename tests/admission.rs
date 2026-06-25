//! The connection-admission barrier (`transport_iroh::admission`): a server that admits a peer
//! unblocks the client's `await_admission`; a server that rejects (closes without admitting) makes
//! `await_admission` return an error, so a rejected client fails fast instead of re-dialing forever.
//! Hermetic loopback iroh connections.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test code; panics are assertion failures"
)]
use std::time::Duration;

use koh::transport_iroh::admission::{admit, await_admission};
use koh::transport_iroh::{bind_endpoint_local, generate_secret_key, loopback_addr, ALPN};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admit_unblocks_await_admission() {
    let server = bind_endpoint_local(generate_secret_key(), true)
        .await
        .expect("bind server");
    let client = bind_endpoint_local(generate_secret_key(), false)
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
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reject_surfaces_as_error() {
    let server = bind_endpoint_local(generate_secret_key(), true)
        .await
        .expect("bind server");
    let client = bind_endpoint_local(generate_secret_key(), false)
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
}
