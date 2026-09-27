//! The admission ack.
//!
//! Once the allowlist admits a peer, the server opens a bi-stream and writes one byte. It is not
//! authentication (the handshake did that); it lets the client tell "admitted" from a rejection,
//! which closes the connection, so a rejected client fails fast instead of redialing. The server
//! opens the stream and the client accepts it: the other way round both would wait.

use std::io;

use iroh::endpoint::Connection;

/// The single byte the server writes once a peer is authorized.
const ADMIT: u8 = 1;

/// Errors awaiting admission on the client.
#[derive(Debug, thiserror::Error)]
pub enum AdmissionError {
    /// The admission stream failed, usually because the server rejected us.
    #[error("admission stream error: {0}")]
    Stream(#[from] io::Error),
    /// The stream carried another byte; koh's server never sends one.
    #[error("server did not admit the connection")]
    Rejected,
}

/// Server side: admit the peer. Opening the stream can wait on the client, so the caller bounds it.
pub async fn admit(conn: &Connection) -> Result<(), io::Error> {
    let (mut send, _recv) = conn.open_bi().await.map_err(io::Error::other)?;
    send.write_all(&[ADMIT]).await.map_err(io::Error::other)?;
    let _ = send.finish();
    Ok(())
}

/// Client side: await the admission ack.
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
