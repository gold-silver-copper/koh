//! The passphrase nonce-challenge handshake over a real loopback iroh connection.

use rmosh_transport_iroh::auth::AuthError;
use rmosh_transport_iroh::{auth, bind_endpoint_local, generate_secret_key, loopback_addr, ALPN};

/// Run one handshake round over a fresh loopback connection and return (server, client) results.
async fn round(
    server_pass: Option<&'static str>,
    client_pass: Option<&'static str>,
) -> (Result<(), AuthError>, Result<(), AuthError>) {
    let server = bind_endpoint_local(generate_secret_key(), true)
        .await
        .expect("bind server");
    let client = bind_endpoint_local(generate_secret_key(), false)
        .await
        .expect("bind client");
    let server_addr = loopback_addr(&server);

    // Accept on a clone so the original `server` endpoint stays alive (keeping the connection up).
    let server_ep = server.clone();
    let accept = tokio::spawn(async move {
        let incoming = server_ep.accept().await.expect("accept");
        incoming.await.expect("server handshake")
    });

    let client_conn = client.connect(server_addr, ALPN).await.expect("connect");
    let server_conn = accept.await.expect("accept join");

    // Both handshakes must run concurrently: server opens the bi-stream, client accepts it.
    let result = tokio::join!(
        auth::handshake_server(&server_conn, server_pass),
        auth::handshake_client(&client_conn, client_pass),
    );
    // Keep endpoints alive until here.
    drop((server, client));
    result
}

#[tokio::test]
async fn passphrase_handshake_over_iroh() {
    // (a) no passphrase on either side -> both sides succeed.
    let (sr, cr) = round(None, None).await;
    assert!(sr.is_ok(), "no-passphrase server: {sr:?}");
    assert!(cr.is_ok(), "no-passphrase client: {cr:?}");

    // (b) matching passphrase -> the server accepts.
    let (sr, _cr) = round(Some("hunter2"), Some("hunter2")).await;
    assert!(sr.is_ok(), "matching passphrase should pass, got {sr:?}");

    // (c) wrong passphrase -> the server rejects with the typed `ChallengeFailed` (not a
    // transport error), so the accept loop can tell a real rejection from a dropped connection.
    let (sr, _cr) = round(Some("hunter2"), Some("nope")).await;
    assert!(
        matches!(sr, Err(AuthError::ChallengeFailed)),
        "wrong passphrase must be rejected server-side as ChallengeFailed, got {sr:?}"
    );
}
