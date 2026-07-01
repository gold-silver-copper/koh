//! End-to-end tests of the optional FIDO2 / security-key second factor over real loopback iroh
//! connections. These drive the exact functions `koh serve` / `koh connect` call, in the same order
//! (endpoint-id allowlist → `admit_with_sk` → attach), using a software [`SimAuthenticator`] in place
//! of a hardware token (it produces byte-identical OpenSSH `sk-ssh-ed25519` / `sk-ecdsa-sha2-nistp256`
//! signatures, so the server verifier can't tell the difference — which is the point).
//!
//! Covered:
//! - default endpoint-id auth still works (a server with no `--require-sk`), even for an SK-capable client;
//! - `--require-sk` rejects a client that presents no SK proof;
//! - a security key that is not on the allowlist is rejected;
//! - a valid endpoint id + a valid SK proof is admitted;
//! - an unallowlisted endpoint id is rejected *before* any SK challenge (the signer is never invoked).
//!
//! (Signature tampering, replay, cross-server relay, and missing-touch rejection are covered as unit
//! tests in `transport_iroh::sk_auth`, which exercise the verifier directly.)

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "integration test code; panics are assertion failures"
)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use koh::transport_iroh::admission::{
    admit, admit_with_sk, await_admission, await_admission_with_sk, AdmissionError, AdmitError,
};
use koh::transport_iroh::sk_auth::{ClientSkCtx, ServerSk, SimAuthenticator, SkSigner, NONCE_LEN};
use koh::transport_iroh::{bind_endpoint_local, generate_secret_key, loopback_addr, ALPN};

/// A signer wrapper that records how many times it is asked to sign — used to prove the security-key
/// step never runs for a peer rejected by the endpoint-id allowlist.
struct CountingSigner {
    inner: SimAuthenticator,
    calls: Arc<AtomicUsize>,
}

impl SkSigner for CountingSigner {
    fn public_key_blob(&self) -> Vec<u8> {
        self.inner.public_key_blob()
    }
    fn sign(&self, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.sign(data)
    }
}

/// A valid endpoint id plus a valid security-key proof is admitted, and the server verifies the proof.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn valid_id_and_valid_sk_proof_is_admitted() {
    let server = bind_endpoint_local(generate_secret_key(), true)
        .await
        .unwrap();
    let client = bind_endpoint_local(generate_secret_key(), false)
        .await
        .unwrap();
    let addr = loopback_addr(&server);
    let server_id = *server.id().as_bytes();
    let client_id = *client.id().as_bytes();

    let auth = SimAuthenticator::new([1u8; 32], b"ssh:");
    let allow = ServerSk::from_keys(vec![auth.public_key()]);
    let signer: Arc<dyn SkSigner> = Arc::new(auth);

    let accept = tokio::spawn(async move {
        let incoming = server.accept().await.unwrap();
        let conn = incoming.await.unwrap();
        let peer = *conn.remote_id().as_bytes();
        let res = admit_with_sk(&conn, &server_id, &peer, &allow).await;
        // Hold the connection so the client can read the ADMIT ack before it closes.
        tokio::time::sleep(Duration::from_millis(200)).await;
        res
    });

    let conn = client.connect(addr, ALPN).await.unwrap();
    let ctx = ClientSkCtx {
        server_id,
        client_id,
        signer,
    };
    let client_res = await_admission_with_sk(&conn, &ctx).await;
    assert!(
        client_res.is_ok(),
        "a valid id + valid sk proof must be admitted, got {client_res:?}"
    );
    let server_res = accept.await.unwrap();
    let outcome = server_res.expect("server verified the proof");
    assert!(
        outcome.sk_fingerprint.is_some(),
        "the server records the verified key's fingerprint"
    );
}

/// The same happy path with an **ecdsa-sk** (NIST P-256) key, over real loopback iroh.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn valid_id_and_valid_ecdsa_sk_proof_is_admitted() {
    let server = bind_endpoint_local(generate_secret_key(), true)
        .await
        .unwrap();
    let client = bind_endpoint_local(generate_secret_key(), false)
        .await
        .unwrap();
    let addr = loopback_addr(&server);
    let server_id = *server.id().as_bytes();
    let client_id = *client.id().as_bytes();

    let auth = SimAuthenticator::new_ecdsa(b"ssh:");
    let allow = ServerSk::from_keys(vec![auth.public_key()]);
    let signer: Arc<dyn SkSigner> = Arc::new(auth);

    let accept = tokio::spawn(async move {
        let incoming = server.accept().await.unwrap();
        let conn = incoming.await.unwrap();
        let peer = *conn.remote_id().as_bytes();
        let res = admit_with_sk(&conn, &server_id, &peer, &allow).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        res
    });

    let conn = client.connect(addr, ALPN).await.unwrap();
    let ctx = ClientSkCtx {
        server_id,
        client_id,
        signer,
    };
    let client_res = await_admission_with_sk(&conn, &ctx).await;
    assert!(
        client_res.is_ok(),
        "a valid id + valid ecdsa-sk proof must be admitted, got {client_res:?}"
    );
    assert!(
        accept
            .await
            .unwrap()
            .expect("server verified")
            .sk_fingerprint
            .is_some(),
        "the server records the verified ecdsa key's fingerprint"
    );
}

/// A server with `--require-sk` rejects a client that presents no security-key proof (a stock client
/// that only speaks the plain admission path).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn require_sk_rejects_client_without_proof() {
    let server = bind_endpoint_local(generate_secret_key(), true)
        .await
        .unwrap();
    let client = bind_endpoint_local(generate_secret_key(), false)
        .await
        .unwrap();
    let addr = loopback_addr(&server);
    let server_id = *server.id().as_bytes();

    let enrolled = SimAuthenticator::new([2u8; 32], b"ssh:");
    let allow = ServerSk::from_keys(vec![enrolled.public_key()]);

    let accept = tokio::spawn(async move {
        let incoming = server.accept().await.unwrap();
        let conn = incoming.await.unwrap();
        let peer = *conn.remote_id().as_bytes();
        // Bound it so a non-responding client can't hang the test forever.
        tokio::time::timeout(
            Duration::from_secs(5),
            admit_with_sk(&conn, &server_id, &peer, &allow),
        )
        .await
    });

    let conn = client.connect(addr, ALPN).await.unwrap();
    // A stock client only reads the one-byte ack; it sees the CHALLENGE tag and treats it as a reject.
    let client_res = await_admission(&conn).await;
    assert!(
        client_res.is_err(),
        "a client with no security-key proof must be rejected under --require-sk"
    );
    // Close so the server's pending read errors out promptly rather than waiting on the grace timeout.
    drop(conn);

    let server_res = accept.await.unwrap().expect("server did not hang");
    assert!(
        server_res.is_err(),
        "the server must not admit a client that sent no valid proof"
    );
}

/// A security key that is not on the server's allowlist is rejected (the endpoint id is fine).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unallowlisted_security_key_is_rejected() {
    let server = bind_endpoint_local(generate_secret_key(), true)
        .await
        .unwrap();
    let client = bind_endpoint_local(generate_secret_key(), false)
        .await
        .unwrap();
    let addr = loopback_addr(&server);
    let server_id = *server.id().as_bytes();
    let client_id = *client.id().as_bytes();

    let enrolled = SimAuthenticator::new([3u8; 32], b"ssh:");
    let attacker = SimAuthenticator::new([4u8; 32], b"ssh:");
    let allow = ServerSk::from_keys(vec![enrolled.public_key()]);
    let signer: Arc<dyn SkSigner> = Arc::new(attacker);

    let accept = tokio::spawn(async move {
        let incoming = server.accept().await.unwrap();
        let conn = incoming.await.unwrap();
        let peer = *conn.remote_id().as_bytes();
        let res = admit_with_sk(&conn, &server_id, &peer, &allow).await;
        // The real cli closes on failure; mimic that so the client's ADMIT read fails fast.
        if res.is_err() {
            conn.close(2u32.into(), b"security-key auth failed");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        res
    });

    let conn = client.connect(addr, ALPN).await.unwrap();
    let ctx = ClientSkCtx {
        server_id,
        client_id,
        signer,
    };
    let client_res = await_admission_with_sk(&conn, &ctx).await;
    assert!(
        client_res.is_err(),
        "a proof from a key not on the allowlist must be rejected"
    );
    let server_res = accept.await.unwrap();
    assert!(
        matches!(server_res, Err(AdmitError::SkAuth(_))),
        "the server rejects an unallowlisted key as an SK auth failure, got {server_res:?}"
    );
}

/// Default endpoint-id auth is unchanged: a server that did NOT enable `--require-sk` admits normally,
/// even for a client that is configured with a security key (the signer is simply unused).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn default_id_auth_still_works_for_sk_capable_client() {
    let server = bind_endpoint_local(generate_secret_key(), true)
        .await
        .unwrap();
    let client = bind_endpoint_local(generate_secret_key(), false)
        .await
        .unwrap();
    let addr = loopback_addr(&server);
    let server_id = *server.id().as_bytes();
    let client_id = *client.id().as_bytes();

    let auth = SimAuthenticator::new([5u8; 32], b"ssh:");
    let calls = Arc::new(AtomicUsize::new(0));
    let signer: Arc<dyn SkSigner> = Arc::new(CountingSigner {
        inner: auth,
        calls: calls.clone(),
    });

    let accept = tokio::spawn(async move {
        let incoming = server.accept().await.unwrap();
        let conn = incoming.await.unwrap();
        // No SK policy: the plain admission path (unchanged wire).
        admit(&conn).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
    });

    let conn = client.connect(addr, ALPN).await.unwrap();
    let ctx = ClientSkCtx {
        server_id,
        client_id,
        signer,
    };
    let client_res = await_admission_with_sk(&conn, &ctx).await;
    assert!(
        client_res.is_ok(),
        "an sk-capable client must still connect to a no-sk server, got {client_res:?}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "the server didn't challenge, so the client must not have signed"
    );
    accept.await.unwrap();
}

/// An unallowlisted endpoint id is rejected BEFORE any security-key challenge: the server closes on
/// the endpoint-id gate, so the client's signer is never invoked (no touch is ever requested).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unallowlisted_endpoint_id_rejected_before_sk() {
    let server = bind_endpoint_local(generate_secret_key(), true)
        .await
        .unwrap();
    let client = bind_endpoint_local(generate_secret_key(), false)
        .await
        .unwrap();
    let addr = loopback_addr(&server);
    let server_id = *server.id().as_bytes();
    let client_id = *client.id().as_bytes();

    // The client's endpoint id is deliberately NOT in this set.
    let allowed_ids: std::collections::HashSet<_> = [generate_secret_key().public()].into();

    let auth = SimAuthenticator::new([6u8; 32], b"ssh:");
    let calls = Arc::new(AtomicUsize::new(0));
    let signer: Arc<dyn SkSigner> = Arc::new(CountingSigner {
        inner: auth,
        calls: calls.clone(),
    });

    let accept = tokio::spawn(async move {
        let incoming = server.accept().await.unwrap();
        let conn = incoming.await.unwrap();
        // Mirror the server cli order: the endpoint-id allowlist is checked FIRST; an unlisted peer is
        // closed here, before `admit_with_sk` is ever reached — so no challenge is issued.
        let peer = conn.remote_id();
        if !allowed_ids.contains(&peer) {
            conn.close(1u32.into(), b"not authorized");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    });

    let conn = client.connect(addr, ALPN).await.unwrap();
    let ctx = ClientSkCtx {
        server_id,
        client_id,
        signer,
    };
    let client_res = await_admission_with_sk(&conn, &ctx).await;
    assert!(
        client_res.is_err(),
        "an unallowlisted endpoint id must be rejected"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "SK auth must not run for a peer rejected by the endpoint-id allowlist"
    );
    accept.await.unwrap();
}

/// The client rejects a server CHALLENGE that advertises an unsupported SK protocol version instead
/// of trying to sign a transcript the two sides can't agree on — and it must not touch the key first.
/// Locks the client-side version-skew branch in `await_admission_with_sk` (a refactor that dropped or
/// inverted the version check would otherwise pass the whole suite, since every other test uses the
/// single current version).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_rejects_challenge_with_bad_version() {
    let server = bind_endpoint_local(generate_secret_key(), true)
        .await
        .unwrap();
    let client = bind_endpoint_local(generate_secret_key(), false)
        .await
        .unwrap();
    let addr = loopback_addr(&server);
    let server_id = *server.id().as_bytes();
    let client_id = *client.id().as_bytes();

    // The signer must NEVER be asked to sign: the version check precedes any signing.
    let auth = SimAuthenticator::new([7u8; 32], b"ssh:");
    let calls = Arc::new(AtomicUsize::new(0));
    let signer: Arc<dyn SkSigner> = Arc::new(CountingSigner {
        inner: auth,
        calls: calls.clone(),
    });

    // The server hand-rolls a CHALLENGE frame with an unsupported version byte.
    let accept = tokio::spawn(async move {
        let incoming = server.accept().await.unwrap();
        let conn = incoming.await.unwrap();
        let (mut send, _recv) = conn.open_bi().await.unwrap();
        // [CHALLENGE=2][version=0xFF (unsupported)][nonce(NONCE_LEN)]. `CHALLENGE` is admission.rs's
        // private tag; hardcoded here on purpose so this test pins the exact wire byte a real client
        // must recognize.
        let mut frame = vec![2u8, 0xFF];
        frame.extend_from_slice(&[0u8; NONCE_LEN]);
        send.write_all(&frame).await.unwrap();
        let _ = send.finish();
        // Hold the connection open so the failure is the client's version check, not a reset.
        tokio::time::sleep(Duration::from_millis(200)).await;
    });

    let conn = client.connect(addr, ALPN).await.unwrap();
    let ctx = ClientSkCtx {
        server_id,
        client_id,
        signer,
    };
    let res = await_admission_with_sk(&conn, &ctx).await;
    assert!(
        matches!(res, Err(AdmissionError::SkAuth(_))),
        "client must reject an unsupported challenge version as an SkAuth error, got {res:?}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "the client must not sign before agreeing on the protocol version"
    );
    accept.await.unwrap();
}

/// The server's `admit_with_sk` rejects a client response frame whose leading version byte is
/// unsupported, before it parses any key or signature. Locks the server-side version-skew branch in
/// `read_sk_response`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_rejects_response_with_bad_version() {
    let server = bind_endpoint_local(generate_secret_key(), true)
        .await
        .unwrap();
    let client = bind_endpoint_local(generate_secret_key(), false)
        .await
        .unwrap();
    let addr = loopback_addr(&server);
    let server_id = *server.id().as_bytes();

    let enrolled = SimAuthenticator::new([8u8; 32], b"ssh:");
    let allow = ServerSk::from_keys(vec![enrolled.public_key()]);

    let accept = tokio::spawn(async move {
        let incoming = server.accept().await.unwrap();
        let conn = incoming.await.unwrap();
        let peer = *conn.remote_id().as_bytes();
        // Bound it so a mis-framed exchange can't hang the test forever.
        tokio::time::timeout(
            Duration::from_secs(5),
            admit_with_sk(&conn, &server_id, &peer, &allow),
        )
        .await
    });

    let conn = client.connect(addr, ALPN).await.unwrap();
    // Accept the server's control stream, read its CHALLENGE (tag + version + nonce), then reply with
    // a response frame carrying an unsupported version byte. `read_sk_response` rejects on the version
    // before it reads the pubkey/signature fields, so that byte alone drives the outcome.
    let (mut send, mut recv) = conn.accept_bi().await.unwrap();
    let mut challenge = [0u8; 2 + NONCE_LEN]; // [CHALLENGE][version][nonce]
    recv.read_exact(&mut challenge).await.unwrap();
    send.write_all(&[0xFFu8]).await.unwrap(); // an unsupported response version
    let _ = send.finish();

    let server_res = accept.await.unwrap().expect("server did not hang");
    assert!(
        matches!(server_res, Err(AdmitError::SkAuth(_))),
        "the server must reject an unsupported response version as an SkAuth failure, got {server_res:?}"
    );
    drop(conn);
}

/// Live-agent smoke test (opt-in: `cargo test --test sk_auth -- --ignored`). Validates the ssh-agent
/// client framing against a REAL agent by signing arbitrary data with whatever key the agent holds and
/// verifying the returned signature — the same request/response path a hardware `ed25519-sk` key uses,
/// minus the FIDO2 wrapping (a non-sk key signs the data directly). Skips cleanly if no agent/key.
#[cfg(unix)]
#[tokio::test]
#[ignore = "requires a running ssh-agent with a loaded key; run with --ignored"]
async fn agent_client_signs_against_live_agent() {
    use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
    use koh::transport_iroh::sk_auth::{agent_list_identities, agent_sign};
    use std::path::PathBuf;

    let Some(sock) = std::env::var_os("SSH_AUTH_SOCK") else {
        eprintln!("no $SSH_AUTH_SOCK; skipping");
        return;
    };
    let sock = PathBuf::from(sock);
    let ids = agent_list_identities(&sock).expect("list agent identities");
    // Find an ed25519 identity (`ssh-ed25519`); the signature is a plain, software-verifiable one.
    let Some((blob, comment)) = ids
        .into_iter()
        .find(|(b, _)| b.len() > 15 && &b[4..15] == b"ssh-ed25519")
    else {
        eprintln!("no ssh-ed25519 key in the agent; skipping");
        return;
    };
    eprintln!("signing test data with agent key: {comment}");

    let data = b"koh-agent-framing-smoke-test";
    let sig_blob = agent_sign(&sock, &blob, data).expect("agent signs");

    // Parse the ed25519 public key (string "ssh-ed25519" | string pk32) and signature
    // (string "ssh-ed25519" | string sig64), then verify — proving the agent framing round-trips.
    let pk = ssh_string_at(&blob, ssh_string_end(&blob, 0)).expect("pk");
    let sig = ssh_string_at(&sig_blob, ssh_string_end(&sig_blob, 0)).expect("sig");
    let vk = VerifyingKey::from_bytes(&pk.try_into().expect("32-byte pk")).expect("valid pk");
    let signature = Signature::from_slice(&sig).expect("64-byte sig");
    vk.verify(data, &signature)
        .expect("the agent's signature must verify — agent framing is correct");
}

/// Return the byte offset just past the SSH `string` that starts at `pos` (its 4-byte length + body).
#[cfg(unix)]
fn ssh_string_end(buf: &[u8], pos: usize) -> usize {
    let len = u32::from_be_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]) as usize;
    pos + 4 + len
}

/// Return the bytes of the SSH `string` that starts at `pos`.
#[cfg(unix)]
fn ssh_string_at(buf: &[u8], pos: usize) -> Option<Vec<u8>> {
    let len = u32::from_be_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]) as usize;
    buf.get(pos + 4..pos + 4 + len).map(<[u8]>::to_vec)
}
