//! Optional passphrase second auth factor (defense-in-depth on top of the node-id allowlist).
//!
//! The connection is already cryptographically authenticated to a node public key and gated by
//! the allowlist. A shared passphrase adds a second factor for the residual case where a client
//! key leaks: the leaked-but-still-allowlisted key could be used for **online** passphrase
//! guessing. The mitigation is a per-guess CPU/memory cost plus per-peer rate limiting (the
//! limiter lives in [`crate::transport_iroh::ratelimit`]).
//!
//! The server opens a reliable bi-stream, sends a fresh random nonce, and verifies
//! `BLAKE3(K || nonce)` where `K = Argon2id(passphrase, salt)` — so the **passphrase never
//! crosses the wire**, each handshake is replay-unique (a captured response is worthless against
//! a different nonce), and every guess costs the attacker a full Argon2id derivation. The
//! constant-time compare ([`constant_time_eq_32`]) closes the response-comparison timing oracle.
//!
//! Ported from `moshers-iroh/src/auth.rs` (identical iroh 1.0 + blake3 1 API). Stream direction
//! is deliberate: the **server opens** the bi-stream and the **client accepts** it — inverting
//! that deadlocks both sides on their `*_bi()` calls.

use std::collections::HashMap;
use std::io;
use std::sync::{LazyLock, Mutex};

use constant_time_eq::constant_time_eq_32;
use iroh::endpoint::Connection;
use zeroize::Zeroizing;

/// Tag byte: the server requires no passphrase.
const NO_PASS: u8 = 0;
/// Tag byte: a nonce challenge follows; the client must answer with `BLAKE3(passphrase||nonce)`.
const PASS_REQUIRED: u8 = 1;

/// A fresh 32-byte challenge nonce straight from the OS CSPRNG.
///
/// Using `OsRng` directly (the same pattern as `generate_secret_key` in `lib.rs`) rather than
/// `SecretKey::generate().to_bytes()` keeps nonce generation independent of iroh's key type and
/// makes the security-relevant source explicit: each handshake must be replay-unique, so the
/// nonce must come from a real CSPRNG, never a counter or a reused value.
fn fresh_nonce() -> [u8; 32] {
    use rand::RngCore;
    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Argon2id parameters for the passphrase KDF: 64 MiB memory, 3 iterations, 1 lane, 32-byte
/// output. Argon2's role here is purely the **work factor** — it makes each online guess of a
/// leaked-but-allowlisted client's passphrase cost real CPU/memory (the per-peer rate limiter
/// then bounds the guess rate). It is *not* password storage, which is why the salt below is
/// fixed rather than random.
#[expect(
    clippy::expect_used,
    reason = "Params::new only errors on out-of-range values; these are compile-time constants"
)]
fn kdf_params() -> argon2::Params {
    argon2::Params::new(64 * 1024, 3, 1, Some(32)).expect("static Argon2id params are in range")
}

/// The fixed, deterministic KDF salt. **Both peers must derive the same PSK from a shared
/// passphrase**, so a per-derivation random salt — correct for password *storage* — would be
/// exactly wrong here: it would make the two sides disagree. We take 16 bytes of a
/// domain-separated BLAKE3 hash of a constant; the security comes from the Argon2id work factor,
/// not from salt secrecy.
fn kdf_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&blake3::hash(b"koh-pass-kdf-v1").as_bytes()[..16]);
    salt
}

/// Derive the 32-byte pre-shared key `K = Argon2id(passphrase, salt)`. Pure and deterministic, so
/// the client and server independently derive the **same** `K` from the same passphrase.
///
/// The result is wrapped in [`Zeroizing`] so the derived key is wiped from the heap on drop. This
/// reduces how long the PSK lingers in memory; the passphrase itself reaches us only as a `&str`
/// view into the caller's [`secrecy::SecretString`], exposed solely for this call (argv/env still
/// remain OS-visible — prefer `$KOH_PASSPHRASE` over `--passphrase`).
#[expect(
    clippy::expect_used,
    reason = "hash_password_into only errors on invalid params/output-len, fixed valid here"
)]
fn derive_psk(passphrase: &str) -> Zeroizing<[u8; 32]> {
    let argon = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        kdf_params(),
    );
    let mut psk = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase.as_bytes(), &kdf_salt(), psk.as_mut_slice())
        .expect("Argon2id derivation with valid static params and a 32-byte output cannot fail");
    psk
}

/// Derived PSKs keyed by a BLAKE3 hash of their passphrase (never the plaintext); values are
/// zeroized when dropped.
type PskCache = HashMap<[u8; 32], Zeroizing<[u8; 32]>>;

/// Process-wide cache of derived PSKs so reconnects (and repeated handshakes) don't re-run the
/// deliberately-expensive KDF. The map never holds the passphrase itself.
/// (The `.lock()` unwrap is a poison check, not peer-influenced input.)
static PSK_CACHE: LazyLock<Mutex<PskCache>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// Fetch `K` for `passphrase`, deriving + caching it on first use ("derive once at startup",
/// realized as derive-on-first-handshake-then-reuse).
#[expect(
    clippy::expect_used,
    reason = "a poisoned cache mutex is a panic-elsewhere bug, not peer-influenced input"
)]
fn cached_psk(passphrase: &str) -> Zeroizing<[u8; 32]> {
    let key = *blake3::hash(passphrase.as_bytes()).as_bytes();
    {
        let cache = PSK_CACHE.lock().expect("PSK cache mutex poisoned");
        if let Some(psk) = cache.get(&key) {
            return psk.clone();
        }
    }
    let psk = derive_psk(passphrase);
    PSK_CACHE
        .lock()
        .expect("PSK cache mutex poisoned")
        .insert(key, psk.clone());
    psk
}

/// The challenge response `BLAKE3(K || nonce)`. Both sides compute it; the server compares the
/// client's against its own in constant time. A fixed 64-byte buffer avoids a heap allocation.
fn challenge_response(psk: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(psk);
    input[32..].copy_from_slice(nonce);
    *blake3::hash(&input).as_bytes()
}

/// Errors from the passphrase nonce-challenge handshake (mirrors the `SetupError` pattern).
///
/// No `anyhow`, so the typed failure is matchable — the server distinguishes a transport drop from
/// a genuine auth rejection. The QUIC bi-stream surfaces several distinct error types
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
/// sends a fresh 32-byte nonce and verifies the client's `BLAKE3(K || nonce)` response in constant
/// time, where `K` is the cached Argon2id-derived PSK.
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
            // Derive (or fetch the cached) PSK before touching the network so the expensive KDF
            // can't be triggered repeatedly by an attacker who hangs up mid-handshake.
            let psk = cached_psk(pass);
            // A fresh 32-byte nonce straight from the OS CSPRNG (replay-uniqueness depends on it).
            let nonce = fresh_nonce();
            let mut msg = Vec::with_capacity(33);
            msg.push(PASS_REQUIRED);
            msg.extend_from_slice(&nonce);
            send.write_all(&msg).await.map_err(io::Error::other)?;

            let mut resp = [0u8; 32];
            recv.read_exact(&mut resp).await.map_err(io::Error::other)?;
            let expect = challenge_response(&psk, &nonce);
            let _ = send.finish();
            // Constant-time compare: no early-exit timing oracle on the response bytes.
            if !constant_time_eq_32(&resp, &expect) {
                return Err(AuthError::ChallengeFailed);
            }
        }
    }
    Ok(())
}

/// Client side of the passphrase handshake (run after connect, before wrapping the connection).
///
/// Reads the challenge and, if a passphrase is required, answers with `BLAKE3(K || nonce)` where
/// `K = Argon2id(passphrase, salt)`. A client with no passphrase derives `K` from the empty
/// string, so the rejection (if the server requires one) surfaces on the server side.
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
        let psk = cached_psk(passphrase.unwrap_or(""));
        let resp = challenge_response(&psk, &nonce);
        send.write_all(&resp).await.map_err(io::Error::other)?;
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

    #[test]
    fn successive_nonces_differ() {
        // Replay-uniqueness: each handshake must use a fresh CSPRNG nonce. A collision across
        // independent draws is cryptographically negligible, so any repeat is a regression
        // (e.g. accidentally reusing a constant or a counter).
        let a = fresh_nonce();
        let b = fresh_nonce();
        assert_ne!(a, b, "two OsRng nonces must differ");
        assert_ne!(a, [0u8; 32], "a nonce must not be all-zero");
    }

    #[test]
    fn derive_psk_is_deterministic_and_both_peers_agree() {
        // Determinism is the whole point: the client and server independently call the SAME
        // derivation, so equal passphrases MUST yield equal PSKs (else the handshake can't pass).
        // Deref the Zeroizing wrappers to compare the key bytes (Zeroizing deliberately omits
        // PartialEq to discourage non-constant-time key comparisons).
        let server_k = derive_psk("correct horse battery staple");
        let client_k = derive_psk("correct horse battery staple");
        assert_eq!(*server_k, *client_k, "both peers must derive the same PSK");
        // The cached path must equal a fresh derivation.
        assert_eq!(*cached_psk("correct horse battery staple"), *server_k);
        // A different passphrase yields a different PSK.
        assert_ne!(
            *server_k,
            *derive_psk("wrong horse"),
            "distinct passphrases -> distinct PSKs"
        );
        // The fixed salt is stable (so the PSK is reproducible across runs).
        assert_eq!(kdf_salt(), kdf_salt());
    }

    #[test]
    fn correct_response_verifies_and_wrong_one_does_not() {
        // The challenge/compare logic, exercised without iroh: BLAKE3(K || nonce) compared with
        // constant_time_eq_32. Correct -> Ok-equivalent (true), wrong -> rejected (false). No
        // timing assertion (constant-time is a property of the comparator, not measured here).
        let psk = cached_psk("hunter2");
        let nonce = fresh_nonce();
        let good = challenge_response(&psk, &nonce);
        assert!(
            constant_time_eq_32(&good, &challenge_response(&psk, &nonce)),
            "the correct response must verify"
        );
        // A response from the wrong passphrase's PSK must not verify.
        let bad = challenge_response(&cached_psk("nope"), &nonce);
        assert!(
            !constant_time_eq_32(&good, &bad),
            "a wrong response must be rejected"
        );
        // The same PSK against a different nonce must not verify (replay protection).
        let other_nonce = fresh_nonce();
        assert!(
            !constant_time_eq_32(&good, &challenge_response(&psk, &other_nonce)),
            "a response is bound to its nonce"
        );
    }
}
