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

use anyhow::{bail, Result};
use iroh::endpoint::Connection;

/// Tag byte: the server requires no passphrase.
const NO_PASS: u8 = 0;
/// Tag byte: a nonce challenge follows; the client must answer with `BLAKE3(passphrase||nonce)`.
const PASS_REQUIRED: u8 = 1;

/// Server side of the passphrase handshake (run after the allowlist check, before the session).
///
/// With no passphrase configured it announces [`NO_PASS`] and returns immediately. Otherwise it
/// sends a fresh 32-byte nonce and verifies the client's `BLAKE3(passphrase || nonce)` response.
pub async fn handshake_server(conn: &Connection, passphrase: Option<&str>) -> Result<()> {
    let (mut send, mut recv) = conn.open_bi().await?;
    match passphrase {
        None => {
            send.write_all(&[NO_PASS]).await?;
            let _ = send.finish();
        }
        Some(pass) => {
            // 32 random bytes from the OS RNG (reuse iroh's key generator as a CSPRNG source).
            let nonce = iroh::SecretKey::generate().to_bytes();
            let mut msg = Vec::with_capacity(33);
            msg.push(PASS_REQUIRED);
            msg.extend_from_slice(&nonce);
            send.write_all(&msg).await?;

            let mut resp = [0u8; 32];
            recv.read_exact(&mut resp).await?;
            let expect = blake3::hash(&[pass.as_bytes(), &nonce[..]].concat());
            let _ = send.finish();
            if resp != *expect.as_bytes() {
                bail!("passphrase challenge failed");
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
pub async fn handshake_client(conn: &Connection, passphrase: Option<&str>) -> Result<()> {
    let (mut send, mut recv) = conn.accept_bi().await?;
    let mut tag = [0u8; 1];
    recv.read_exact(&mut tag).await?;
    if tag[0] == PASS_REQUIRED {
        let mut nonce = [0u8; 32];
        recv.read_exact(&mut nonce).await?;
        let pass = passphrase.unwrap_or("");
        let resp = blake3::hash(&[pass.as_bytes(), &nonce[..]].concat());
        send.write_all(resp.as_bytes()).await?;
        let _ = send.finish();
    }
    Ok(())
}
