//! Optional passphrase second auth factor (defense-in-depth on top of the node-id allowlist).
//!
//! The connection is already cryptographically authenticated to a node public key and gated by
//! the allowlist. A shared passphrase adds a second factor for the case where a client key
//! leaks. The server opens a reliable bi-stream, sends a fresh random nonce, and verifies
//! `BLAKE3(passphrase || nonce)` — so the **passphrase never crosses the wire** and each
//! handshake is replay-unique (a captured response is worthless against a different nonce).
//!
//! Ported from `moshers-iroh/src/auth.rs` (identical iroh 1.0 + blake3 1 API). Stream direction
//! is deliberate: the **server opens** the bi-stream and the **client accepts** it — inverting
//! that deadlocks both sides on their `*_bi()` calls.

use std::io;

use iroh::endpoint::Connection;

/// Tag byte: the server requires no passphrase.
const NO_PASS: u8 = 0;
/// Tag byte: a nonce challenge follows; the client must answer with `BLAKE3(passphrase||nonce)`.
const PASS_REQUIRED: u8 = 1;

/// Errors from the passphrase nonce-challenge handshake (mirrors the `SetupError` pattern; no
/// `anyhow` so the typed failure is matchable — the server distinguishes a transport drop from a
/// genuine auth rejection). The QUIC bi-stream surfaces several distinct error types
/// (`ConnectionError`/`WriteError`/`ReadExactError`); they are folded into one `io::Error` so the
/// `Stream` variant has a single `#[from]` source. Binaries absorb `AuthError` via anyhow's
/// blanket `From`.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// The underlying QUIC bi-stream failed (open/accept/read/write).
    #[error("auth stream error: {0}")]
    Stream(#[from] io::Error),
    /// The client's response did not match the expected challenge (wrong/missing passphrase).
    #[error("passphrase challenge failed")]
    ChallengeFailed,
}

/// Server side of the passphrase handshake (run after the allowlist check, before the session).
///
/// With no passphrase configured it announces [`NO_PASS`] and returns immediately. Otherwise it
/// sends a fresh 32-byte nonce and verifies the client's `BLAKE3(passphrase || nonce)` response.
pub async fn handshake_server(
    conn: &Connection,
    passphrase: Option<&str>,
) -> Result<(), AuthError> {
    let (mut send, mut recv) = conn.open_bi().await.map_err(io::Error::other)?;
    match passphrase {
        None => {
            send.write_all(&[NO_PASS]).await.map_err(io::Error::other)?;
            let _ = send.finish();
        }
        Some(pass) => {
            // 32 random bytes from the OS RNG (reuse iroh's key generator as a CSPRNG source).
            let nonce = iroh::SecretKey::generate().to_bytes();
            let mut msg = Vec::with_capacity(33);
            msg.push(PASS_REQUIRED);
            msg.extend_from_slice(&nonce);
            send.write_all(&msg).await.map_err(io::Error::other)?;

            let mut resp = [0u8; 32];
            recv.read_exact(&mut resp).await.map_err(io::Error::other)?;
            let expect = blake3::hash(&[pass.as_bytes(), &nonce[..]].concat());
            let _ = send.finish();
            if resp != *expect.as_bytes() {
                return Err(AuthError::ChallengeFailed);
            }
        }
    }
    Ok(())
}

/// Client side of the passphrase handshake (run after connect, before wrapping the connection).
///
/// Reads the challenge and, if a passphrase is required, answers with
/// `BLAKE3(passphrase || nonce)`. A client with no passphrase hashes the empty string, so the
/// rejection (if the server requires one) surfaces on the server side.
pub async fn handshake_client(
    conn: &Connection,
    passphrase: Option<&str>,
) -> Result<(), AuthError> {
    let (mut send, mut recv) = conn.accept_bi().await.map_err(io::Error::other)?;
    let mut tag = [0u8; 1];
    recv.read_exact(&mut tag).await.map_err(io::Error::other)?;
    if tag[0] == PASS_REQUIRED {
        let mut nonce = [0u8; 32];
        recv.read_exact(&mut nonce)
            .await
            .map_err(io::Error::other)?;
        let pass = passphrase.unwrap_or("");
        let resp = blake3::hash(&[pass.as_bytes(), &nonce[..]].concat());
        send.write_all(resp.as_bytes())
            .await
            .map_err(io::Error::other)?;
        let _ = send.finish();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_error_variants_are_constructible_and_reachable() {
        // ChallengeFailed is the auth-rejection path the server's accept loop matches on (so it
        // can distinguish a real rejection from a transport drop / timeout).
        let rejected = AuthError::ChallengeFailed;
        assert_eq!(rejected.to_string(), "passphrase challenge failed");
        // The Stream variant carries the folded bi-stream error via its `#[from] io::Error`.
        let io_err = io::Error::new(io::ErrorKind::UnexpectedEof, "stream closed");
        let stream: AuthError = io_err.into();
        assert!(matches!(stream, AuthError::Stream(_)));
        assert!(stream.to_string().contains("auth stream error"));
        // Binaries absorb AuthError via anyhow (the client wraps it with `.context()?`).
        let absorbed: anyhow::Error = AuthError::ChallengeFailed.into();
        assert!(absorbed.to_string().contains("challenge failed"));
    }
}
