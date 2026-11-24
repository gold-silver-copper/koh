//! Iroh QUIC transport glue: server/client endpoints, direct/relay dialing,
//! and TLS-keying-material bound Ed25519 client authentication.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use iroh::endpoint::{
    BindOpts, ConnectError, ConnectingError, Connection, ConnectionError, IdleTimeout,
    QuicTransportConfig, RecvStream, SendStream, TransportErrorCode, VarInt, presets,
};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey};

use crate::keys::Route;
use crate::proto::{ALPN, CloseCode, KeyProof, MAX_PROOF, recv_msg, send_msg};
use crate::{KohError, Result};

const PROOF_LABEL: &[u8] = b"koh/19 client proof";

fn transport_config(interactive: bool) -> QuicTransportConfig {
    let (idle_ms, keepalive) = if interactive {
        (30_000, Duration::from_secs(5))
    } else {
        (15_000, Duration::from_secs(2))
    };
    QuicTransportConfig::builder()
        .keep_alive_interval(keepalive)
        .max_idle_timeout(Some(IdleTimeout::from(VarInt::from_u32(idle_ms))))
        .max_concurrent_bidi_streams(VarInt::from_u32(16))
        // (Nothing reads a unidirectional stream: a peer is given none to fill.)
        .max_concurrent_uni_streams(VarInt::from_u32(0))
        .build()
}

/// Binds a server endpoint, optionally listening on an explicit UDP `bind` address for direct dialing.
pub async fn bind_server(
    secret: SecretKey,
    bind: Option<SocketAddr>,
    disable_relay: bool,
) -> Result<Endpoint> {
    let mut builder = Endpoint::builder(presets::N0)
        .secret_key(secret)
        .alpns(vec![ALPN.to_vec()])
        .transport_config(transport_config(true));
    if disable_relay {
        builder = builder.relay_mode(RelayMode::Disabled);
    }
    if let Some(addr) = bind {
        builder = builder
            .bind_addr_with_opts(addr, BindOpts::default())
            .map_err(|e| KohError::usage(format!("invalid bind address {addr}: {e}")))?;
    }
    builder
        .bind()
        .await
        .map_err(|e| KohError::failed(format!("bind server endpoint: {e}")))
}

/// Binds a client endpoint and connects to `server_id` (optionally via direct `SocketAddr` or custom relay).
pub async fn connect_server(
    secret: SecretKey,
    server_id: EndpointId,
    route: Option<Route>,
    interactive: bool,
) -> Result<(Endpoint, EndpointAddr, Connection)> {
    let mut builder = Endpoint::builder(presets::N0)
        .secret_key(secret.clone())
        .transport_config(transport_config(interactive));
    let mut addr = EndpointAddr::new(server_id);
    match route {
        Some(Route::Direct(sock)) => {
            builder = builder.relay_mode(RelayMode::Disabled);
            let local = if sock.is_ipv4() {
                SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
            } else {
                SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0))
            };
            builder = builder
                .bind_addr_with_opts(local, BindOpts::default())
                .map_err(|e| KohError::unreachable(format!("bind local addr: {e}")))?;
            addr = addr.with_ip_addr(sock);
        }
        Some(Route::Relay(url)) => {
            builder = builder.relay_mode(RelayMode::Custom(url.clone().into()));
            addr = addr.with_relay_url(url);
        }
        None => {}
    }
    let endpoint = builder
        .bind()
        .await
        .map_err(|e| KohError::unreachable(format!("bind client endpoint: {e}")))?;
    let conn = dial(&endpoint, addr.clone()).await?;
    Ok((endpoint, addr, conn))
}

/// A connection to the server at `addr`, in fifteen seconds or not at all.
pub async fn dial(endpoint: &Endpoint, addr: EndpointAddr) -> Result<Connection> {
    tokio::time::timeout(Duration::from_secs(15), endpoint.connect(addr, ALPN))
        .await
        .map_err(|_| KohError::unreachable("timed out dialing server"))?
        .map_err(|e| match refused(&e) {
            true => busy(),
            false => KohError::unreachable(format!("cannot reach server: {e}")),
        })
}

/// Whether the server was reached and refused the connection before it began (QUIC's
/// CONNECTION_REFUSED): a koh server does that when it has no place left, not even to say so.
fn refused(err: &ConnectError) -> bool {
    let closed = match err {
        ConnectError::Connection { source, .. } => source,
        ConnectError::Connecting {
            source: ConnectingError::ConnectionError { source, .. },
            ..
        } => source,
        _ => return false,
    };
    matches!(closed, ConnectionError::ConnectionClosed(close) if close.error_code == TransportErrorCode::CONNECTION_REFUSED)
}

fn busy() -> KohError {
    KohError::new(
        crate::Exit::BUSY,
        "busy",
        "server busy: too many connections at once",
    )
}

fn proof_payload(conn: &Connection) -> Result<Vec<u8>> {
    let mut exported = [0u8; 32];
    conn.export_keying_material(&mut exported, PROOF_LABEL, &[])
        .map_err(|e| KohError::internal(format!("export keying material: {e:?}")))?;
    let mut msg = Vec::with_capacity(PROOF_LABEL.len() + exported.len());
    msg.extend_from_slice(PROOF_LABEL);
    msg.extend_from_slice(&exported);
    Ok(msg)
}

/// Opens an authenticated bidirectional stream: writes TLS-bound `KeyProof` first.
pub async fn open_authed_stream(
    conn: &Connection,
    secret: &SecretKey,
) -> Result<(SendStream, RecvStream)> {
    let (mut send, recv) = conn
        .open_bi()
        .await
        .map_err(|e| map_conn_err(conn, format!("open stream: {e}")))?;
    let sig = secret.sign(&proof_payload(conn)?);
    let proof = KeyProof {
        key: *secret.public().as_bytes(),
        signature: sig.to_bytes().to_vec(),
    };
    send_msg(&mut send, &proof, MAX_PROOF)
        .await
        .map_err(|e| close_error(conn).unwrap_or(e))?;
    Ok((send, recv))
}

/// Verifies the client's TLS-bound `KeyProof` on an accepted bidirectional stream.
pub async fn verify_client(conn: &Connection, recv: &mut RecvStream) -> Result<EndpointId> {
    let proof: KeyProof = recv_msg(recv, MAX_PROOF).await?;
    let id = EndpointId::from_bytes(&proof.key)
        .map_err(|e| KohError::refused(format!("invalid client key: {e}")))?;
    let sig_bytes: [u8; 64] = proof
        .signature
        .try_into()
        .map_err(|_| KohError::refused("invalid signature length"))?;
    let sig = iroh::Signature::from_bytes(&sig_bytes);
    id.verify(&proof_payload(conn)?, &sig)
        .map_err(|e| KohError::refused(format!("invalid key proof: {e}")))?;
    Ok(id)
}

pub fn close_with(conn: &Connection, code: CloseCode) {
    conn.close(VarInt::from_u32(code as u32), b"");
}

/// Why the server closed the connection, if it did and said: refused, or busy.
pub fn close_error(conn: &Connection) -> Option<KohError> {
    let Some(iroh::endpoint::ConnectionError::ApplicationClosed(close)) = conn.close_reason()
    else {
        return None;
    };
    match CloseCode::from_u64(close.error_code.into_inner()) {
        Some(CloseCode::Refused) => Some(KohError::refused("server refused this client key")),
        Some(CloseCode::Busy) => Some(busy()),
        _ => None,
    }
}

pub fn map_conn_err(conn: &Connection, fallback: String) -> KohError {
    close_error(conn).unwrap_or_else(|| KohError::unreachable(fallback))
}
