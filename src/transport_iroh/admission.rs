//! Connection admission barrier (post-allowlist).
//!
//! After the server admits a peer — its node-id is on the allowlist — it opens a bi-stream and
//! writes a single ADMIT byte; the client awaits it. This is **not** authentication:
//! the peer's node-id is already authenticated by iroh's QUIC/TLS handshake, and the allowlist is the
//! authorization gate. The ack exists only as a synchronization point so the **client** can cleanly
//! distinguish "admitted" from a deliberate server rejection (which closes the connection). Without
//! it a rejected client would re-dial in the reconnect loop forever instead of failing fast with the
//! server's close reason.
//!
//! Stream direction is deliberate: the **server opens** the bi-stream and the **client accepts** it —
//! inverting that deadlocks both sides on their `*_bi()` calls.
//!
//! ## Optional security-key gate (`--require-sk`)
//!
//! When the operator enables the FIDO2 second factor, the *same* server-opened control stream carries
//! a challenge/response step **before** the admission byte (see [`admit_with_sk`] /
//! [`await_admission_with_sk`]). The stream begins with a one-byte tag — [`ADMIT`] (the historical,
//! wire-unchanged no-SK path) or [`CHALLENGE`] (SK required) — so old clients and the no-SK path are
//! byte-for-byte unchanged, and a client that can't satisfy an SK challenge fails fast with a clear
//! reason. The security-key proof is verified (in [`sk_auth`](super::sk_auth)) *before* the admission
//! byte is ever written, so the server never attaches a session, spawns a PTY, or reads terminal I/O
//! for a peer that hasn't proven possession of an allowlisted hardware key.

use std::io;

use iroh::endpoint::{Connection, RecvStream};
use rand::RngCore as _;

use super::sk_auth;

/// The first control-stream byte once a peer is authorized (and, under `--require-sk`, has also proven
/// its security key). Value `1` is unchanged from the original single-byte admission ack.
const ADMIT: u8 = 1;

/// The first control-stream byte when the server requires a security-key proof: a challenge follows.
const CHALLENGE: u8 = 2;

/// Cap on each length-prefixed field (public-key / signature blob) the server will read from a client
/// during the SK exchange. Real blobs are ~100 bytes; this bounds a hostile client's allocation.
const MAX_SK_BLOB: usize = 2048;

/// Errors awaiting admission on the client.
#[derive(Debug, thiserror::Error)]
pub enum AdmissionError {
    /// The admission bi-stream failed (open/accept/read) — typically the server closing on rejection.
    #[error("admission stream error: {0}")]
    Stream(#[from] io::Error),
    /// The server's admission stream carried a byte other than ADMIT. Currently unreachable — the
    /// server only ever writes ADMIT (a reject closes the connection, surfacing as `Stream`) — kept
    /// as a defensive guard against a non-conforming or forward-incompatible server.
    #[error("server did not admit the connection")]
    Rejected,
    /// The client could not satisfy the server's security-key challenge (no signer configured, a
    /// signing failure, or an unsupported challenge). The message is safe to show the user.
    #[error("{0}")]
    SkAuth(String),
}

/// Outcome of a successful admission — records which security key (if any) proved the connection, for
/// the server's audit log.
#[derive(Debug)]
pub struct AdmitOutcome {
    /// The fingerprint of the security key that satisfied the challenge, when `--require-sk` is on.
    pub sk_fingerprint: Option<String>,
}

impl AdmitOutcome {
    /// The no-security-key outcome (plain allowlist admission).
    pub const fn none() -> Self {
        Self {
            sk_fingerprint: None,
        }
    }
}

/// Errors from the server-side admission / SK gate.
#[derive(Debug, thiserror::Error)]
pub enum AdmitError {
    /// The control stream failed (open/write/read) — typically the client vanishing mid-handshake.
    #[error("admission stream error: {0}")]
    Io(#[from] io::Error),
    /// The client's security-key proof was missing, malformed, or did not verify. The message is
    /// non-sensitive (it never contains key material) and doubles as the connection close reason.
    #[error("security-key auth failed: {0}")]
    SkAuth(String),
}

/// Server side: signal admission after the allowlist check passes.
///
/// Fast in the common case (opening a QUIC stream and buffering one byte), but `open_bi()` can wait
/// on stream-flow-control credit, so a stalling client is bounded by the caller's own short timeout
/// (`koh serve`'s 3s admission deadline in `server::cli`), not relied on to never block.
pub async fn admit(conn: &Connection) -> Result<(), io::Error> {
    let (mut send, _recv) = conn.open_bi().await.map_err(io::Error::other)?;
    send.write_all(&[ADMIT]).await.map_err(io::Error::other)?;
    let _ = send.finish();
    Ok(())
}

/// Client side: await the server's admission ack. A closed connection (the server rejected us) or a
/// missing/unexpected byte surfaces as an error the caller turns into a clean "not authorized".
pub async fn await_admission(conn: &Connection) -> Result<(), AdmissionError> {
    let (_send, mut recv) = conn.accept_bi().await.map_err(io::Error::other)?;
    let mut byte = [0u8; 1];
    recv.read_exact(&mut byte).await.map_err(io::Error::other)?;
    if byte[0] == ADMIT {
        Ok(())
    } else {
        Err(AdmissionError::Rejected)
    }
}

/// Server side: run the security-key challenge/response, then (only if it verifies) admit.
///
/// Called instead of [`admit`] when `--require-sk` is set, and **before** any session attach / PTY
/// spawn.
///
/// On the same server-opened bi-stream it: writes `[CHALLENGE][version][nonce]`, reads the client's
/// `[version][pubkey][signature]` response, verifies it against `sk` for the transcript bound to
/// `(server_id, peer_id, nonce)`, and on success writes `[ADMIT]`. A verification failure returns
/// `Err(AdmitError::SkAuth(reason))` **without** writing ADMIT — the caller closes the connection with
/// that reason.
pub async fn admit_with_sk(
    conn: &Connection,
    server_id: &[u8; 32],
    peer_id: &[u8; 32],
    sk: &sk_auth::ServerSk,
) -> Result<AdmitOutcome, AdmitError> {
    let (mut send, mut recv) = conn.open_bi().await.map_err(io::Error::other)?;

    // A fresh nonce for THIS connection (never reused), so a signature captured elsewhere can't be
    // replayed here — the transcript binds this nonce.
    let mut nonce = [0u8; sk_auth::NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let mut challenge = Vec::with_capacity(2 + nonce.len());
    challenge.push(CHALLENGE);
    challenge.push(sk_auth::SK_VERSION);
    challenge.extend_from_slice(&nonce);
    send.write_all(&challenge).await.map_err(io::Error::other)?;

    let resp = read_sk_response(&mut recv).await?;
    let transcript = sk_auth::build_transcript(server_id, peer_id, &nonce);
    let verified = sk
        .verify(&transcript, &resp)
        .map_err(|e| AdmitError::SkAuth(e.to_string()))?;

    // Verified: only now is the admission byte written.
    send.write_all(&[ADMIT]).await.map_err(io::Error::other)?;
    let _ = send.finish();
    Ok(AdmitOutcome {
        sk_fingerprint: Some(verified.fingerprint),
    })
}

/// Read the client's SK response frame — `[u8 version][u16 pubkey_len][pubkey][u16 sig_len][sig]` —
/// with every length bounded by [`MAX_SK_BLOB`] so a hostile client can't drive an unbounded read.
async fn read_sk_response(recv: &mut RecvStream) -> Result<sk_auth::SkResponse, AdmitError> {
    let mut version = [0u8; 1];
    recv.read_exact(&mut version)
        .await
        .map_err(io::Error::other)?;
    if version[0] != sk_auth::SK_VERSION {
        return Err(AdmitError::SkAuth(
            "unsupported security-key protocol version".to_string(),
        ));
    }
    let pubkey_blob = read_bounded_field(recv).await?;
    let signature_blob = read_bounded_field(recv).await?;
    Ok(sk_auth::SkResponse {
        pubkey_blob,
        signature_blob,
    })
}

/// Read one `u16`-length-prefixed field, refusing anything larger than [`MAX_SK_BLOB`].
async fn read_bounded_field(recv: &mut RecvStream) -> Result<Vec<u8>, AdmitError> {
    let mut len_buf = [0u8; 2];
    recv.read_exact(&mut len_buf)
        .await
        .map_err(io::Error::other)?;
    let len = u16::from_be_bytes(len_buf) as usize;
    if len > MAX_SK_BLOB {
        return Err(AdmitError::SkAuth(
            "security-key field exceeds the maximum length".to_string(),
        ));
    }
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await.map_err(io::Error::other)?;
    Ok(buf)
}

/// Client side: await admission, satisfying a security-key challenge if the server issues one.
///
/// Reads the control stream's leading tag: [`ADMIT`] means the server did not require a security key
/// (admitted immediately — the configured signer is simply unused); [`CHALLENGE`] means it did, so we
/// sign the bound transcript with the configured key and send the response, then await the admission
/// byte. A `CHALLENGE` with no signer, or a signing failure, surfaces as `AdmissionError::SkAuth`.
pub async fn await_admission_with_sk(
    conn: &Connection,
    ctx: &sk_auth::ClientSkCtx,
) -> Result<(), AdmissionError> {
    let (mut send, mut recv) = conn.accept_bi().await.map_err(io::Error::other)?;
    let mut tag = [0u8; 1];
    recv.read_exact(&mut tag).await.map_err(io::Error::other)?;
    match tag[0] {
        // Server didn't ask for a security key — behave exactly like the plain admission path.
        ADMIT => Ok(()),
        CHALLENGE => {
            let mut version = [0u8; 1];
            recv.read_exact(&mut version)
                .await
                .map_err(io::Error::other)?;
            if version[0] != sk_auth::SK_VERSION {
                return Err(AdmissionError::SkAuth(
                    "server requested an unsupported security-key protocol version".to_string(),
                ));
            }
            let mut nonce = [0u8; sk_auth::NONCE_LEN];
            recv.read_exact(&mut nonce)
                .await
                .map_err(io::Error::other)?;

            let transcript = sk_auth::build_transcript(&ctx.server_id, &ctx.client_id, &nonce);
            // Signing may block on a hardware touch, so run it off the async worker.
            let signer = std::sync::Arc::clone(&ctx.signer);
            let data = transcript.clone();
            let signature_blob = tokio::task::spawn_blocking(move || signer.sign(&data))
                .await
                .map_err(|e| {
                    AdmissionError::SkAuth(format!("security-key signing task failed: {e}"))
                })?
                .map_err(|e| AdmissionError::SkAuth(format!("security-key signing failed: {e}")))?;
            let pubkey_blob = ctx.signer.public_key_blob();
            if pubkey_blob.len() > MAX_SK_BLOB || signature_blob.len() > MAX_SK_BLOB {
                return Err(AdmissionError::SkAuth(
                    "security-key blob is too large to send".to_string(),
                ));
            }

            let mut frame = Vec::with_capacity(5 + pubkey_blob.len() + signature_blob.len());
            frame.push(sk_auth::SK_VERSION);
            frame.extend_from_slice(&(pubkey_blob.len() as u16).to_be_bytes());
            frame.extend_from_slice(&pubkey_blob);
            frame.extend_from_slice(&(signature_blob.len() as u16).to_be_bytes());
            frame.extend_from_slice(&signature_blob);
            send.write_all(&frame).await.map_err(io::Error::other)?;

            let mut ack = [0u8; 1];
            recv.read_exact(&mut ack).await.map_err(io::Error::other)?;
            if ack[0] == ADMIT {
                Ok(())
            } else {
                Err(AdmissionError::Rejected)
            }
        }
        _ => Err(AdmissionError::Rejected),
    }
}
