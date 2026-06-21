//! # rmosh-transport-iroh
//!
//! The iroh glue: endpoint setup, a persistent node identity, dial-by-endpoint-id, and a
//! thin [`IrohChannel`] over a `Connection` that the SSP driver uses to ship datagrams and
//! read the path RTT. Everything QUIC-shaped (encryption, key exchange, NAT traversal,
//! relay fallback, roaming/migration, RTT measurement) is iroh's job; this crate just
//! exposes the few primitives the protocol above it needs.
//!
//! ## Datagrams, not streams
//!
//! The steady SSP flow rides QUIC **unreliable datagrams** ([`IrohChannel::send`] /
//! [`IrohChannel::recv`]). Oversized instructions are handled upstream by the
//! [`rmosh_wire`] fragmenter (each fragment fits [`IrohChannel::max_datagram_size`]), so we
//! never put the steady flow on a reliable stream — that would reintroduce the
//! head-of-line blocking mosh exists to avoid.

use std::path::Path;
use std::time::Duration;

use bytes::Bytes;
use iroh::endpoint::{presets, Connection, ConnectionError, PathId, VarInt};
use iroh::{Endpoint, EndpointId, SecretKey};
use rmosh_wire::DEFAULT_MAX_DATAGRAM;

/// The ALPN that identifies the rmosh protocol on the wire.
pub const ALPN: &[u8] = b"rmosh/iroh/1";

/// Errors from endpoint/identity setup.
#[derive(Debug, thiserror::Error)]
pub enum SetupError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("secret key file is not 32 bytes of hex")]
    BadKeyFile,
    #[error("could not parse endpoint id: {0}")]
    BadEndpointId(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Load a persistent [`SecretKey`] from `path`, or generate + persist one if absent.
///
/// The file holds the 32-byte secret as lowercase hex. A stable key gives the server a
/// stable [`EndpointId`], mirroring iroh-ssh's `--persist`.
pub fn load_or_create_secret_key(path: &Path) -> Result<SecretKey, SetupError> {
    if path.exists() {
        let text = std::fs::read_to_string(path)?;
        let bytes = data_encoding::HEXLOWER_PERMISSIVE
            .decode(text.trim().as_bytes())
            .map_err(|_| SetupError::BadKeyFile)?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| SetupError::BadKeyFile)?;
        Ok(SecretKey::from_bytes(&arr))
    } else {
        let sk = generate_secret_key();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, data_encoding::HEXLOWER.encode(&sk.to_bytes()))?;
        Ok(sk)
    }
}

/// Generate a fresh random secret key (uses the OS RNG so it's independent of iroh's rand version).
pub fn generate_secret_key() -> SecretKey {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    SecretKey::from_bytes(&bytes)
}

/// Parse an [`EndpointId`] from its canonical (hex) string form, or the n0 base32 form.
pub fn parse_endpoint_id(s: &str) -> Result<EndpointId, SetupError> {
    s.trim()
        .parse::<EndpointId>()
        .map_err(|e| SetupError::BadEndpointId(e.to_string()))
}

/// The canonical (hex) string form of an [`EndpointId`], suitable for copy/paste.
pub fn format_endpoint_id(id: &EndpointId) -> String {
    id.to_string()
}

/// Build an iroh [`Endpoint`] with the `presets::N0` profile (relay + DNS discovery, so a
/// bare endpoint id is dialable). `accept` registers our ALPN so the endpoint can accept
/// incoming connections (server side).
pub async fn bind_endpoint(secret: SecretKey, accept: bool) -> Result<Endpoint, SetupError> {
    let mut builder = Endpoint::builder(presets::N0).secret_key(secret);
    if accept {
        builder = builder.alpns(vec![ALPN.to_vec()]);
    }
    let ep = builder.bind().await.map_err(|e| SetupError::Other(e.into()))?;
    Ok(ep)
}

/// A datagram channel over a single iroh [`Connection`], plus a one-shot reliable
/// uni-stream escape hatch for state too big to fragment comfortably.
#[derive(Clone)]
pub struct IrohChannel {
    conn: Connection,
}

impl IrohChannel {
    pub fn new(conn: Connection) -> Self {
        IrohChannel { conn }
    }

    /// The peer's stable identity.
    pub fn remote_id(&self) -> EndpointId {
        self.conn.remote_id()
    }

    /// Borrow the underlying connection (for advanced use / lifecycle).
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    /// Send one datagram. Failures (peer congestion, too-large, unsupported) are *dropped* on
    /// purpose: the SSP resends the current state on the next tick, so a lost datagram is a
    /// non-event. Returns whether it was handed to the transport.
    pub fn send(&self, datagram: &[u8]) -> bool {
        match self.conn.send_datagram(Bytes::copy_from_slice(datagram)) {
            Ok(()) => true,
            Err(e) => {
                tracing::trace!(error = %e, len = datagram.len(), "datagram send dropped");
                false
            }
        }
    }

    /// Await the next inbound datagram.
    pub async fn recv(&self) -> Result<Bytes, ConnectionError> {
        self.conn.read_datagram().await
    }

    /// The current datagram payload budget (path-MTU dependent; can change over the
    /// connection's life). Falls back to a conservative default if datagrams report no size.
    pub fn max_datagram_size(&self) -> usize {
        self.conn
            .max_datagram_size()
            .unwrap_or(DEFAULT_MAX_DATAGRAM)
            .max(64)
    }

    /// The smoothed path RTT in milliseconds, preferring the currently-selected path. `None`
    /// before any path is established (e.g. mid-holepunch).
    pub fn rtt_ms(&self) -> Option<f64> {
        let to_ms = |d: Duration| d.as_secs_f64() * 1000.0;
        if let Some(p) = self.conn.paths().iter().find(|p| p.is_selected()) {
            return Some(to_ms(p.rtt()));
        }
        if let Some(p) = self.conn.paths().iter().next() {
            return Some(to_ms(p.rtt()));
        }
        self.conn.rtt(PathId::ZERO).map(to_ms)
    }

    /// Send a large blob over a one-shot reliable uni-stream (escape hatch for state too big
    /// to want to fragment over datagrams). The default path fragments over datagrams; this
    /// is kept for huge repaints.
    pub async fn send_reliable(&self, data: &[u8]) -> anyhow::Result<()> {
        let mut send = self.conn.open_uni().await?;
        send.write_all(data).await?;
        send.finish()?; // NOTE: noq's finish() is synchronous and returns Result.
        Ok(())
    }

    /// Receive a blob from a peer's one-shot reliable uni-stream (pairs with [`send_reliable`](Self::send_reliable)).
    pub async fn recv_reliable(&self, size_limit: usize) -> anyhow::Result<Vec<u8>> {
        let mut recv = self.conn.accept_uni().await?;
        Ok(recv.read_to_end(size_limit).await?)
    }

    /// Immediately close the connection with an application code + reason.
    pub fn close(&self, code: u32, reason: &[u8]) {
        self.conn.close(VarInt::from_u32(code), reason);
    }

    /// Resolve when the connection closes, yielding the reason.
    pub async fn closed(&self) -> ConnectionError {
        self.conn.closed().await
    }
}

/// A monotonic millisecond clock for driving the SSP scheduler, anchored at a base instant.
#[derive(Debug, Clone, Copy)]
pub struct MonoClock {
    base: tokio::time::Instant,
}

impl Default for MonoClock {
    fn default() -> Self {
        Self::new()
    }
}

impl MonoClock {
    pub fn new() -> Self {
        MonoClock {
            base: tokio::time::Instant::now(),
        }
    }

    /// Milliseconds since this clock was created.
    pub fn now_ms(&self) -> u64 {
        self.base.elapsed().as_millis() as u64
    }

    /// The base instant, for computing absolute sleep deadlines from ms offsets.
    pub fn base(&self) -> tokio::time::Instant {
        self.base
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_key_roundtrips_through_disk() {
        let dir = std::env::temp_dir().join(format!("rmosh-key-test-{}", std::process::id()));
        let path = dir.join("id.key");
        let _ = std::fs::remove_dir_all(&dir);

        let sk1 = load_or_create_secret_key(&path).unwrap();
        let sk2 = load_or_create_secret_key(&path).unwrap();
        assert_eq!(sk1.to_bytes(), sk2.to_bytes(), "second load must reuse the key");

        // The endpoint id is stable and round-trips through its string form.
        let id = sk1.public();
        let s = format_endpoint_id(&id);
        assert_eq!(parse_endpoint_id(&s).unwrap(), id);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(parse_endpoint_id("not-a-real-endpoint-id").is_err());
    }
}
