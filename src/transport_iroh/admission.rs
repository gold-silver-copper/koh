//! Connection admission barrier (post-allowlist).
//!
//! After the server admits a peer — its node-id is on the allowlist (or `--allow-any`) — it opens a
//! bi-stream and writes a single ADMIT byte; the client awaits it. This is **not** authentication:
//! the peer's node-id is already authenticated by iroh's QUIC/TLS handshake, and the allowlist is the
//! authorization gate. The ack exists only as a synchronization point so the **client** can cleanly
//! distinguish "admitted" from a deliberate server rejection (which closes the connection). Without
//! it a rejected client would re-dial in the reconnect loop forever instead of failing fast with the
//! server's close reason.
//!
//! Stream direction is deliberate: the **server opens** the bi-stream and the **client accepts** it —
//! inverting that deadlocks both sides on their `*_bi()` calls.

use std::io;

use iroh::endpoint::Connection;

/// The single byte the server writes once a peer is authorized.
const ADMIT: u8 = 1;

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
