//! The connection-admission barrier (`transport_iroh::admission`): a server that admits a peer
//! completes the client's `dial`; a server that refuses (closes without admitting) makes `dial` a
//! fatal verdict, so a refused client fails fast instead of re-dialing forever.
//! Hermetic loopback iroh connections.

use std::time::Duration;

use koh::transport_iroh::admission::{admit, dial, refuse, Disconnect, Refusal};
use koh::transport_iroh::{bind_endpoint_local, generate_secret_key, loopback_addr};

#[test]
fn admit_completes_the_dial() {
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
            let _link = admit(conn).await.expect("admit");
            // Hold the connection briefly so the client's accept_bi sees the stream.
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        dial(&client, addr).await.expect("client must be admitted");
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
            refuse(conn, Refusal::NotAuthorized);
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        match dial(&client, addr).await {
            Err(Disconnect::Fatal(e)) => assert!(
                format!("{e:#}").contains("server rejected the connection: not authorized"),
                "{e:#}"
            ),
            Ok(_) => panic!("a server that closes without admitting must not admit"),
            Err(e) => panic!("a refusal is a verdict, not {e:?}"),
        }
        accept.await.expect("accept task");
    });
}

/// The runtime for a test. `#[tokio::test]` is not used: its expansion `allow`s
/// `clippy::expect_used`, which koh forbids, and a `forbid` rejects that `allow`.
fn runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
}
