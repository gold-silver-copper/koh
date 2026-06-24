//! Optional passphrase second auth factor (defense-in-depth on top of the node-id allowlist).
//!
//! The connection is already cryptographically authenticated to a node public key and gated by the
//! allowlist. A shared passphrase adds a second factor for the residual case where a client key
//! leaks (the leaked-but-still-allowlisted key could be used for **online** passphrase guessing,
//! bounded by the per-peer rate limiter in [`crate::transport_iroh::ratelimit`]) and, crucially,
//! for the case where a user is lured into dialing a *malicious* server's NodeId.
//!
//! ## A balanced PAKE (SPAKE2), not a hash challenge
//!
//! The handshake is **SPAKE2** ([RFC 9382], the CFRG-class balanced PAKE) followed by explicit
//! **mutual key confirmation**. Both peers map the passphrase through the memory-hard
//! [`cached_psk`] (Argon2id) to a 32-byte value, run SPAKE2 over Ed25519 with it, derive a shared
//! key, and each proves knowledge by a confirmation tag bound to the full transcript. This buys two
//! properties a plain `BLAKE3(K || nonce)` challenge cannot:
//!
//! 1. **No offline-crackable transcript.** SPAKE2's messages are group elements independent of the
//!    passphrase to anyone who doesn't complete the protocol, so a malicious server a client merely
//!    *dials* learns nothing it can grind offline. Guessing is forced *online* — one guess per live
//!    handshake — where the rate limiter and the Argon2id work factor bound it. This closes KOH-03.
//! 2. **Mutual authentication.** The confirmation is two-way: a server that does not know the
//!    passphrase cannot produce a matching confirmation tag, so the client **refuses the session if
//!    the server's confirmation fails** — an impostor server can't authenticate. The tag is not
//!    offline-crackable, so completing the (sub-second) exchange before refusing leaks nothing an
//!    abrupt abort wouldn't, and it lets the server report a clean verdict rather than a drop.
//!
//! Freshness/replay: each SPAKE2 message carries a fresh random scalar, and the confirmation binds
//! both messages, so a replayed transcript pairs with a fresh peer message and fails. The
//! comparisons use [`constant_time_eq_32`] (no timing oracle).
//!
//! Stream direction is deliberate: the **server opens** the bi-stream and the **client accepts** it
//! — inverting that deadlocks both sides on their `*_bi()` calls.
//!
//! [RFC 9382]: https://www.rfc-editor.org/rfc/rfc9382

use std::collections::HashMap;
use std::io;
use std::sync::{LazyLock, Mutex};

use constant_time_eq::constant_time_eq_32;
use iroh::endpoint::{Connection, RecvStream};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use zeroize::Zeroizing;

/// Tag byte: the server requires no passphrase.
const NO_PASS: u8 = 0;
/// Tag byte: a SPAKE2 PAKE handshake follows (the server's SPAKE2 message is appended).
const PAKE_REQUIRED: u8 = 1;
/// Verdict byte the server sends after verifying the client's confirmation, so the **client** learns
/// the outcome instead of optimistically reporting success and then being silently dropped.
const VERDICT_OK: u8 = 1;
const VERDICT_REJECT: u8 = 0;

/// Upper bound on a peer's framed SPAKE2 message. Ed25519 SPAKE2 messages are ~33 bytes; this cap
/// means a hostile length byte can never make us allocate more than a few dozen bytes.
const MAX_PAKE_MSG: usize = 64;

/// SPAKE2 identity string — part of the session binding, so it must match on both peers.
const PAKE_IDENTITY: &[u8] = b"koh-pake-v1";
/// Domain-separation labels for the two confirmation directions (distinct so a tag for one
/// direction can never be reflected as the other).
const SERVER_CONFIRM_LABEL: &[u8] = b"server";
const CLIENT_CONFIRM_LABEL: &[u8] = b"client";

/// Argon2id parameters for the passphrase KDF: 64 MiB memory, 3 iterations, 1 lane, 32-byte output.
/// Argon2 is the SPAKE2 memory-hard map of the passphrase. The work factor burdens the **guesser**:
/// each distinct online guess forces the attacker to compute a full Argon2id derivation, so combined
/// with the per-peer [`FailureLimiter`](crate::transport_iroh::ratelimit) the guess rate is bounded.
/// The honest server derives its own value only **once** (then [`cached_psk`] reuses it), so this is
/// not a per-guess server cost. It is *not* password storage, which is why the salt is fixed.
#[expect(
    clippy::expect_used,
    reason = "Params::new only errors on out-of-range values; these are compile-time constants"
)]
fn kdf_params() -> argon2::Params {
    argon2::Params::new(64 * 1024, 3, 1, Some(32)).expect("static Argon2id params are in range")
}

/// The fixed, deterministic KDF salt. **Both peers must derive the same value from a shared
/// passphrase** (else SPAKE2 yields disagreeing keys), so a per-derivation random salt — correct for
/// password *storage* — would be exactly wrong here. We take 16 bytes of a domain-separated BLAKE3
/// hash of a constant; the security comes from the Argon2id work factor, not from salt secrecy.
fn kdf_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&blake3::hash(b"koh-pass-kdf-v1").as_bytes()[..16]);
    salt
}

/// Derive the 32-byte memory-hard passphrase map `Argon2id(passphrase, salt)`. Pure and
/// deterministic, so the client and server independently derive the **same** value (SPAKE2 then
/// agrees iff the passphrases match).
///
/// The result is wrapped in [`Zeroizing`] so it is wiped from the heap on drop. The passphrase
/// itself reaches us only as a `&str` view into the caller's [`secrecy::SecretString`], exposed
/// solely for this call (argv/env still remain OS-visible — prefer `$KOH_PASSPHRASE`).
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

/// Derived values keyed by a BLAKE3 hash of their passphrase (never the plaintext); values are
/// zeroized when dropped.
type PskCache = HashMap<[u8; 32], Zeroizing<[u8; 32]>>;

/// Process-wide cache of derived Argon2id values so reconnects (and repeated handshakes) don't
/// re-run the deliberately-expensive KDF. The map never holds the passphrase itself.
static PSK_CACHE: LazyLock<Mutex<PskCache>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// Fetch the Argon2id passphrase map, deriving + caching it on first use.
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

/// A direction-labeled key-confirmation tag binding the shared SPAKE2 key to the **full transcript**
/// (both public messages). Different `label`s give the server and client distinct tags (no
/// reflection); the transcript binding prevents splicing a tag across runs. `shared_key` is hashed
/// to a 32-byte BLAKE3 key via the KDF mode before keying the MAC.
///
/// Each field is **length-prefixed** before hashing so the encoding is unambiguous regardless of
/// field lengths — no `(label, server_msg, client_msg)` split can ever collide with another, even
/// if a future label differs in length from the current 6-byte constants.
fn confirm_tag(shared_key: &[u8], label: &[u8], server_msg: &[u8], client_msg: &[u8]) -> [u8; 32] {
    let mac_key = blake3::derive_key("koh-pake-v1 key confirmation", shared_key);
    let mut h = blake3::Hasher::new_keyed(&mac_key);
    for field in [label, server_msg, client_msg] {
        h.update(&(field.len() as u64).to_le_bytes());
        h.update(field);
    }
    *h.finalize().as_bytes()
}

/// Errors from the passphrase PAKE handshake.
///
/// No `anyhow`, so the typed failure is matchable — the server distinguishes a transport drop from a
/// genuine auth rejection. The QUIC bi-stream surfaces several distinct error types
/// (`ConnectionError`/`WriteError`/`ReadExactError`); they are folded into one `io::Error` so the
/// `Stream` variant has a single `#[from]` source. Binaries absorb `AuthError` via anyhow.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// The underlying QUIC bi-stream failed (open/accept/read/write).
    #[error("auth stream error: {0}")]
    Stream(#[from] io::Error),
    /// The PAKE confirmation did not match (wrong/missing passphrase, or a peer that doesn't know
    /// it — including an impostor server).
    #[error("passphrase authentication failed")]
    ChallengeFailed,
}

/// Append a length-prefixed (u8) SPAKE2 message. Messages are tiny (~33 B), so a single-byte length
/// suffices; the cap keeps the reader's allocation bounded on the other side.
fn write_msg(out: &mut Vec<u8>, msg: &[u8]) -> Result<(), AuthError> {
    let len = u8::try_from(msg.len())
        .ok()
        .filter(|&l| l != 0 && usize::from(l) <= MAX_PAKE_MSG)
        .ok_or(AuthError::ChallengeFailed)?;
    out.push(len);
    out.extend_from_slice(msg);
    Ok(())
}

/// Read a length-prefixed SPAKE2 message, refusing a zero or over-[`MAX_PAKE_MSG`] length (so a
/// hostile peer can neither stall nor make us allocate). Returns the raw message bytes.
async fn read_msg(recv: &mut RecvStream) -> Result<Vec<u8>, AuthError> {
    let mut len = [0u8; 1];
    recv.read_exact(&mut len).await.map_err(io::Error::other)?;
    let n = usize::from(len[0]);
    if n == 0 || n > MAX_PAKE_MSG {
        return Err(AuthError::ChallengeFailed);
    }
    let mut buf = vec![0u8; n];
    recv.read_exact(&mut buf).await.map_err(io::Error::other)?;
    Ok(buf)
}

/// Server side of the passphrase handshake (run after the allowlist check, before the session).
///
/// With no passphrase configured it announces [`NO_PASS`] and returns. Otherwise it runs SPAKE2 +
/// mutual key confirmation: announce [`PAKE_REQUIRED`] with its SPAKE2 message, read the client's,
/// derive the shared key, send its confirmation tag, then verify the client's in constant time.
pub async fn handshake_server(
    conn: &Connection,
    passphrase: Option<&str>,
) -> Result<(), AuthError> {
    let (mut send, mut recv) = conn.open_bi().await.map_err(io::Error::other)?;
    let Some(pass) = passphrase else {
        send.write_all(&[NO_PASS]).await.map_err(io::Error::other)?;
        let _ = send.finish();
        return Ok(());
    };
    // Derive (or fetch the cached) Argon2id map BEFORE touching the network so the expensive KDF
    // can't be triggered repeatedly by an attacker who hangs up mid-handshake.
    //
    // Residual (KR-09): `start_symmetric` copies the PSK bytes into spake2's own (non-`Zeroize`)
    // internal state, so a copy of the Argon2id *map* (not the passphrase, which stays in a
    // `SecretString`) lingers on the heap until `state` drops. Bounded by the upstream `spake2`
    // crate; only reachable with a separate local memory-disclosure primitive, and still requires
    // an Argon2id-equivalent grind to relate back to a passphrase. Accepted as-is.
    let psk = cached_psk(pass);
    let (state, server_msg) = Spake2::<Ed25519Group>::start_symmetric(
        &Password::new(psk.as_slice()),
        &Identity::new(PAKE_IDENTITY),
    );

    // Announce PAKE + our SPAKE2 message.
    let mut out = vec![PAKE_REQUIRED];
    write_msg(&mut out, &server_msg)?;
    send.write_all(&out).await.map_err(io::Error::other)?;

    // Receive the client's SPAKE2 message and derive the shared key (a malformed message errors).
    let client_msg = read_msg(&mut recv).await?;
    let shared = Zeroizing::new(
        state
            .finish(&client_msg)
            .map_err(|_| AuthError::ChallengeFailed)?,
    );

    // Mutual key confirmation: send ours, then verify the client's in constant time.
    let server_conf = confirm_tag(&shared, SERVER_CONFIRM_LABEL, &server_msg, &client_msg);
    let expect_client_conf = confirm_tag(&shared, CLIENT_CONFIRM_LABEL, &server_msg, &client_msg);
    send.write_all(&server_conf)
        .await
        .map_err(io::Error::other)?;

    let mut client_conf = [0u8; 32];
    recv.read_exact(&mut client_conf)
        .await
        .map_err(io::Error::other)?;
    let ok = constant_time_eq_32(&client_conf, &expect_client_conf);
    let verdict = if ok { VERDICT_OK } else { VERDICT_REJECT };
    send.write_all(&[verdict]).await.map_err(io::Error::other)?;
    let _ = send.finish();
    if ok {
        Ok(())
    } else {
        Err(AuthError::ChallengeFailed)
    }
}

/// Client side of the passphrase handshake (run after connect, before wrapping the connection).
///
/// On [`PAKE_REQUIRED`] it runs SPAKE2 and **refuses the session unless the server's confirmation
/// tag verifies** — so an impostor server that doesn't know the passphrase is rejected (closes
/// KOH-03). It completes the exchange before refusing so the server gets a clean verdict; the tag is
/// not offline-crackable. A wrong/missing passphrase surfaces as [`AuthError::ChallengeFailed`].
pub async fn handshake_client(
    conn: &Connection,
    passphrase: Option<&str>,
) -> Result<(), AuthError> {
    let (mut send, mut recv) = conn.accept_bi().await.map_err(io::Error::other)?;
    let mut tag = [0u8; 1];
    recv.read_exact(&mut tag).await.map_err(io::Error::other)?;
    match tag[0] {
        PAKE_REQUIRED => {
            let server_msg = read_msg(&mut recv).await?;
            let psk = cached_psk(passphrase.unwrap_or(""));
            let (state, client_msg) = Spake2::<Ed25519Group>::start_symmetric(
                &Password::new(psk.as_slice()),
                &Identity::new(PAKE_IDENTITY),
            );
            // Send our SPAKE2 message, then derive the shared key from the server's.
            let mut out = Vec::new();
            write_msg(&mut out, &client_msg)?;
            send.write_all(&out).await.map_err(io::Error::other)?;
            let shared = Zeroizing::new(
                state
                    .finish(&server_msg)
                    .map_err(|_| AuthError::ChallengeFailed)?,
            );

            // Verify the SERVER's confirmation (mutual auth: an impostor server that doesn't know
            // the passphrase cannot produce it, so `server_ok` is false and we refuse below).
            let expect_server_conf =
                confirm_tag(&shared, SERVER_CONFIRM_LABEL, &server_msg, &client_msg);
            let mut server_conf = [0u8; 32];
            recv.read_exact(&mut server_conf)
                .await
                .map_err(io::Error::other)?;
            let server_ok = constant_time_eq_32(&server_conf, &expect_server_conf);

            // Always complete the exchange (send our confirmation, read the verdict) so the SERVER
            // gets a clean accept/reject instead of a transport error from us hanging up. The
            // confirmation tag is not offline-crackable, so finishing the protocol and then refusing
            // leaks nothing an abrupt abort wouldn't — and an impostor learns no more than the one
            // online-guess bit it gets either way. We refuse the session if the server didn't confirm.
            let client_conf = confirm_tag(&shared, CLIENT_CONFIRM_LABEL, &server_msg, &client_msg);
            send.write_all(&client_conf)
                .await
                .map_err(io::Error::other)?;
            let _ = send.finish();
            let mut verdict = [0u8; 1];
            recv.read_exact(&mut verdict)
                .await
                .map_err(io::Error::other)?;
            if !server_ok || verdict[0] != VERDICT_OK {
                return Err(AuthError::ChallengeFailed);
            }
        }
        NO_PASS => {
            // Fail closed: if the user configured a (non-empty) passphrase but the server doesn't
            // require one, refuse rather than silently dropping the second factor they asked for
            // (KOH-13). Only the exact NodeId the client dialed (iroh-authenticated) can send this.
            if passphrase.is_some_and(|p| !p.is_empty()) {
                return Err(AuthError::ChallengeFailed);
            }
        }
        // Any other tag is a protocol violation, not an implicit "ok" — reject it.
        _ => return Err(AuthError::ChallengeFailed),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_error_variants_are_constructible_and_reachable() {
        // ChallengeFailed is the auth-rejection path the server's accept loop matches on (so it can
        // distinguish a real rejection from a transport drop / timeout).
        let rejected = AuthError::ChallengeFailed;
        assert_eq!(rejected.to_string(), "passphrase authentication failed");
        // The Stream variant carries the folded bi-stream error via its `#[from] io::Error`.
        let io_err = io::Error::new(io::ErrorKind::UnexpectedEof, "stream closed");
        let stream: AuthError = io_err.into();
        assert!(matches!(stream, AuthError::Stream(_)));
        assert!(stream.to_string().contains("auth stream error"));
        // Binaries absorb AuthError via anyhow (the client wraps it with `.context()?`).
        let absorbed: anyhow::Error = AuthError::ChallengeFailed.into();
        assert!(absorbed.to_string().contains("authentication failed"));
    }

    #[test]
    fn derive_psk_is_deterministic_and_both_peers_agree() {
        // Determinism is the whole point: the client and server independently call the SAME
        // derivation, so equal passphrases MUST yield equal maps (else SPAKE2 can't agree).
        let server_k = derive_psk("correct horse battery staple");
        let client_k = derive_psk("correct horse battery staple");
        assert_eq!(
            *server_k, *client_k,
            "both peers must derive the same value"
        );
        // The cached path must equal a fresh derivation.
        assert_eq!(*cached_psk("correct horse battery staple"), *server_k);
        // A different passphrase yields a different value.
        assert_ne!(
            *server_k,
            *derive_psk("wrong horse"),
            "distinct passphrases -> distinct maps"
        );
        // The fixed salt is stable (so the value is reproducible across runs).
        assert_eq!(kdf_salt(), kdf_salt());
    }

    /// Run the full two-sided SPAKE2 + confirmation in-process (no iroh) and return whether BOTH
    /// directions of key confirmation verify — i.e. whether the handshake would succeed.
    fn pake_mutual_confirms(server_pass: &str, client_pass: &str) -> bool {
        let s_psk = cached_psk(server_pass);
        let c_psk = cached_psk(client_pass);
        let (s_state, s_msg) = Spake2::<Ed25519Group>::start_symmetric(
            &Password::new(s_psk.as_slice()),
            &Identity::new(PAKE_IDENTITY),
        );
        let (c_state, c_msg) = Spake2::<Ed25519Group>::start_symmetric(
            &Password::new(c_psk.as_slice()),
            &Identity::new(PAKE_IDENTITY),
        );
        let s_shared = s_state.finish(&c_msg).expect("server finish");
        let c_shared = c_state.finish(&s_msg).expect("client finish");
        // Both sides label the transcript identically: (server_msg = s_msg, client_msg = c_msg).
        let client_verifies_server = constant_time_eq_32(
            &confirm_tag(&s_shared, SERVER_CONFIRM_LABEL, &s_msg, &c_msg),
            &confirm_tag(&c_shared, SERVER_CONFIRM_LABEL, &s_msg, &c_msg),
        );
        let server_verifies_client = constant_time_eq_32(
            &confirm_tag(&c_shared, CLIENT_CONFIRM_LABEL, &s_msg, &c_msg),
            &confirm_tag(&s_shared, CLIENT_CONFIRM_LABEL, &s_msg, &c_msg),
        );
        client_verifies_server && server_verifies_client
    }

    #[test]
    fn matching_passphrases_mutually_confirm_and_mismatched_do_not() {
        // Matching passphrases: both confirmation directions verify -> the handshake succeeds.
        assert!(
            pake_mutual_confirms("hunter2", "hunter2"),
            "matching passphrases must mutually confirm"
        );
        // A wrong client passphrase: SPAKE2 keys diverge -> confirmation fails both ways.
        assert!(
            !pake_mutual_confirms("hunter2", "nope"),
            "a wrong passphrase must fail confirmation"
        );
        // An empty vs a set passphrase must also fail (no accidental open door).
        assert!(
            !pake_mutual_confirms("", "secret"),
            "empty vs set passphrase must fail confirmation"
        );
    }

    #[test]
    fn confirm_tag_is_direction_separated_and_transcript_bound() {
        // The same key + transcript with different direction labels yields different tags (so a
        // server tag can never be replayed as a client tag), and changing the transcript changes
        // the tag (so a tag can't be spliced across handshakes).
        let key = [7u8; 32];
        let (a, b) = (b"AAAA".as_slice(), b"BBBB".as_slice());
        let srv = confirm_tag(&key, SERVER_CONFIRM_LABEL, a, b);
        let cli = confirm_tag(&key, CLIENT_CONFIRM_LABEL, a, b);
        assert_ne!(srv, cli, "direction labels must separate the tags");
        let other_transcript = confirm_tag(&key, SERVER_CONFIRM_LABEL, b, a);
        assert_ne!(
            srv, other_transcript,
            "the tag must bind the (ordered) transcript"
        );
    }

    #[test]
    fn framing_round_trips_and_rejects_bad_lengths() {
        // write_msg frames a small message; an over-cap message is refused (never panics).
        let mut buf = Vec::new();
        write_msg(&mut buf, &[1, 2, 3]).expect("small message frames");
        assert_eq!(buf, vec![3, 1, 2, 3], "length prefix then bytes");
        assert!(
            write_msg(&mut Vec::new(), &[0u8; MAX_PAKE_MSG + 1]).is_err(),
            "an over-cap message must be refused, not truncated"
        );
        assert!(
            write_msg(&mut Vec::new(), &[]).is_err(),
            "a zero-length message must be refused"
        );
    }
}
