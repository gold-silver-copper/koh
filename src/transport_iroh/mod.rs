//! The iroh glue: endpoint setup, the identity key's default path, dial addresses and a
//! connection's path RTT.
//!
//! Everything QUIC-shaped (encryption, NAT traversal, relays, roaming, loss recovery) is iroh's.
//! The key file itself is [`crate::identity::KeyFile`]'s.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use iroh::endpoint::{
    presets, AckFrequencyConfig, BindOpts, Connection, IdleTimeout, PathId, QuicTransportConfig,
    VarInt,
};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, RelayUrl, SecretKey};

pub mod admission;

/// The connection idle timeout is 5 minutes, not iroh's ~30 s, so a short suspend (Android
/// freezing the process, so keepalives stop) is ridden out on the same connection; the client
/// redials after a longer one.
///
/// The server accepts only the client's one message stream; the client, the admission bi-stream
/// and a few frame streams (superseded ones are reset, so few are ever open).
fn koh_transport_config(accept: bool) -> QuicTransportConfig {
    // From a `u32` of milliseconds, unlike from a `Duration`, it cannot fail.
    const IDLE_TIMEOUT_MS: u32 = 300_000;
    let (uni, bidi) = if accept { (1, 0) } else { (8, 1) };
    let config = QuicTransportConfig::builder()
        .keep_alive_interval(Duration::from_secs(5))
        .max_idle_timeout(Some(IdleTimeout::from(VarInt::from_u32(IDLE_TIMEOUT_MS))))
        .max_concurrent_uni_streams(VarInt::from_u32(uni))
        .max_concurrent_bidi_streams(VarInt::from_u32(bidi));
    // The server takes a frame's delivery as its acknowledgement, so it asks the client to
    // acknowledge within a couple of milliseconds rather than QUIC's 25: the next frame is then
    // diffed against the newest screen, and a frame is not resent while its acknowledgement waits.
    // Every other packet is still acknowledged together, as by default.
    if accept {
        let mut frequency = AckFrequencyConfig::default();
        frequency.max_ack_delay(Some(CLIENT_ACK_DELAY));
        config.ack_frequency_config(Some(frequency)).build()
    } else {
        config.build()
    }
}

/// How soon the server asks the client's QUIC stack to acknowledge what it got.
const CLIENT_ACK_DELAY: Duration = Duration::from_millis(2);

/// The ALPN, which is the protocol version ([`crate::proto`]): a peer on another fails the TLS
/// handshake instead of misparsing mid-session.
pub const ALPN: &[u8] = b"koh/3";

/// Errors from endpoint/identity setup.
#[derive(Debug, thiserror::Error)]
pub enum SetupError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("secret key file is invalid, a symlink, or not a regular file")]
    BadKeyFile,
    #[error(
        "{0} is not a koh identity key (expected exactly {KEY_LEN} bytes); remove it with \
         `koh key reset --key-file {0} --yes`, which creates a new identity on next use"
    )]
    NotAKey(String),
    #[error("could not parse endpoint id: {0}")]
    BadEndpointId(String),
    #[error("UDP port {0} is already in use (another koh serve?); stop it or pick another --port")]
    PortInUse(u16),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// The length of a key file: an iroh secret key's raw bytes, and nothing else.
pub const KEY_LEN: usize = 32;

/// koh's config directory, the one place it keeps files: `$XDG_CONFIG_HOME/koh`, else
/// `$HOME/.config/koh`, with no platform-specific or temporary fallback. `None` if neither is set.
fn config_dir_from(
    xdg_config_home: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
) -> Option<std::path::PathBuf> {
    let nonempty = |o: Option<std::ffi::OsString>| o.filter(|v| !v.is_empty());
    if let Some(x) = nonempty(xdg_config_home) {
        return Some(std::path::PathBuf::from(x).join("koh"));
    }
    nonempty(home).map(|h| std::path::PathBuf::from(h).join(".config").join("koh"))
}

/// The default key path for `role` (`"client"` or `"server"`): `<config dir>/<role>.key`. An
/// error, not a fallback, if there is no config dir.
pub fn default_key_path(role: &str) -> Result<std::path::PathBuf, SetupError> {
    config_dir_from(
        std::env::var_os("XDG_CONFIG_HOME"),
        std::env::var_os("HOME"),
    )
    .map(|d| d.join(format!("{role}.key")))
    .ok_or_else(|| {
        SetupError::Other(anyhow::anyhow!(
            "cannot locate ~/.config (neither $XDG_CONFIG_HOME nor $HOME is set); pass --key-file"
        ))
    })
}

/// A new secret key from the OS's randomness, with no fallback: a predictable key is no key.
pub fn generate_secret_key() -> std::io::Result<SecretKey> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)?;
    Ok(SecretKey::from_bytes(&bytes))
}

/// Parse an [`EndpointId`] from its canonical (hex) string form, or the n0 base32 form.
pub fn parse_endpoint_id(s: &str) -> Result<EndpointId, SetupError> {
    s.trim()
        .parse::<EndpointId>()
        .map_err(|e| SetupError::BadEndpointId(e.to_string()))
}

/// A `$KOH_DNS` value: `IP:PORT`, or an `IP` on port 53.
fn parse_dns_spec(spec: &str) -> Option<SocketAddr> {
    let spec = spec.trim();
    spec.parse::<SocketAddr>().ok().or_else(|| {
        spec.parse::<std::net::IpAddr>()
            .ok()
            .map(|ip| SocketAddr::new(ip, 53))
    })
}

/// The nameserver `$KOH_DNS` names, else Google's on Android, else `None` for the system's.
///
/// iroh builds a default resolver for every endpoint, which reads the system config; on Android
/// that goes through a JNI context a bare CLI (Termux) lacks, and panics. An explicit nameserver
/// never reads it.
#[cfg_attr(
    target_os = "android",
    expect(
        clippy::unnecessary_wraps,
        reason = "Android always pins a nameserver (Some); the None arm is desktop-only"
    )
)]
fn discovery_dns_resolver() -> Option<iroh::dns::DnsResolver> {
    use iroh::dns::DnsResolver;
    if let Some(addr) = std::env::var("KOH_DNS")
        .ok()
        .as_deref()
        .and_then(parse_dns_spec)
    {
        return Some(DnsResolver::with_nameserver(addr));
    }
    #[cfg(target_os = "android")]
    {
        Some(DnsResolver::with_nameserver(SocketAddr::from((
            [8, 8, 8, 8],
            53,
        ))))
    }
    #[cfg(not(target_os = "android"))]
    {
        None
    }
}

/// Where an endpoint finds its peers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Network {
    /// n0's relays and DNS discovery, so a bare endpoint id is dialable.
    N0,
    /// No relay and no discovery: dialed by id and socket address (LAN, loopback, tests).
    Local,
    /// Only this self-hosted relay, and no discovery.
    Relay(RelayUrl),
}

/// Bind an endpoint on `network`, [`configure`]d, on UDP `port` for IPv4 and, where the host has
/// it, IPv6; `None` binds ephemeral ports. `accept` lets it accept connections (the server).
///
/// A fixed port lets a client dialing an address find a restarted server where it was. A port in
/// use is [`SetupError::PortInUse`].
pub async fn bind_on(
    secret: SecretKey,
    accept: bool,
    network: &Network,
    port: Option<u16>,
) -> Result<Endpoint, SetupError> {
    let builder = match network {
        Network::N0 => Endpoint::builder(presets::N0),
        Network::Local => Endpoint::builder(presets::Minimal),
        Network::Relay(relay) => {
            Endpoint::builder(presets::Minimal).relay_mode(RelayMode::custom([relay.clone()]))
        }
    };
    let builder = match port {
        // IPv6 as iroh binds it by default: skipped where the host has none.
        Some(port) => builder
            .clear_ip_transports()
            .bind_addr((Ipv4Addr::UNSPECIFIED, port))
            .and_then(|builder| {
                builder.bind_addr_with_opts(
                    (Ipv6Addr::UNSPECIFIED, port),
                    BindOpts::default().set_is_required(false),
                )
            })
            .map_err(|e| SetupError::Other(anyhow::Error::new(e)))?,
        None => builder,
    };
    configure(builder, secret, accept)
        .bind()
        .await
        .map_err(|e| {
            let error = anyhow::Error::new(e);
            let in_use = error.chain().any(|cause| {
                cause
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::AddrInUse)
            });
            match port {
                Some(port) if in_use => SetupError::PortInUse(port),
                _ => SetupError::Other(error),
            }
        })
}

/// Apply koh's identity, transport config, DNS resolver and (when `accept`ing) ALPN to `builder`.
/// Every endpoint koh binds goes through this, tests' included.
pub fn configure(
    builder: iroh::endpoint::Builder,
    secret: SecretKey,
    accept: bool,
) -> iroh::endpoint::Builder {
    let mut builder = builder
        .secret_key(secret)
        .transport_config(koh_transport_config(accept));
    if let Some(resolver) = discovery_dns_resolver() {
        builder = builder.dns_resolver(resolver);
    }
    if accept {
        builder = builder.alpns(vec![ALPN.to_vec()]);
    }
    builder
}

/// Bind an endpoint with n0's relays and DNS discovery, so a bare endpoint id is dialable. `accept`
/// lets it accept connections (the server).
pub async fn bind_endpoint(secret: SecretKey, accept: bool) -> Result<Endpoint, SetupError> {
    bind_on(secret, accept, &Network::N0, None).await
}

/// Bind an endpoint with no relay and no discovery, dialed by id and socket address (LAN,
/// loopback, tests).
pub async fn bind_endpoint_local(secret: SecretKey, accept: bool) -> Result<Endpoint, SetupError> {
    bind_on(secret, accept, &Network::Local, None).await
}

/// `ep`'s address on the IPv4 loopback interface.
pub fn loopback_addr(ep: &Endpoint) -> EndpointAddr {
    let mut addr = EndpointAddr::new(ep.id());
    if let Some(port) = ep
        .bound_sockets()
        .iter()
        .find(|s| s.is_ipv4())
        .map(std::net::SocketAddr::port)
    {
        addr = addr.with_ip_addr(SocketAddr::from(([127, 0, 0, 1], port)));
    }
    addr
}

/// How long closing an endpoint waits for its peers to see the close.
const CLOSE_WAIT: Duration = Duration::from_secs(2);

/// Close `endpoint`, waiting at most [`CLOSE_WAIT`] for its peers to see it; whether they did.
/// iroh waits three probe timeouts of the slowest path, over ten seconds for a vanished peer.
pub(crate) async fn close_endpoint(endpoint: &Endpoint) -> bool {
    tokio::time::timeout(CLOSE_WAIT, endpoint.close())
        .await
        .is_ok()
}

/// A peer's address from its id and a direct socket address.
pub fn direct_addr(id: EndpointId, addr: SocketAddr) -> EndpointAddr {
    EndpointAddr::new(id).with_ip_addr(addr)
}

/// A peer's address from its id and the relay it uses.
pub fn relay_addr(id: EndpointId, relay: RelayUrl) -> EndpointAddr {
    EndpointAddr::new(id).with_relay_url(relay)
}

/// Bind an endpoint whose only relay is `relay` (self-hosted), with no discovery.
pub async fn bind_endpoint_with_relay(
    secret: SecretKey,
    accept: bool,
    relay: RelayUrl,
) -> Result<Endpoint, SetupError> {
    bind_on(secret, accept, &Network::Relay(relay), None).await
}

/// Parse a relay URL string (e.g. `https://relay.example:3340`).
pub fn parse_relay_url(s: &str) -> Result<RelayUrl, SetupError> {
    s.trim()
        .parse::<RelayUrl>()
        .map_err(|e| SetupError::Other(anyhow::anyhow!("bad relay url: {e}")))
}

/// The smoothed round-trip time of `conn`'s selected path, or `None` before any path exists.
pub fn rtt(conn: &Connection) -> Option<Duration> {
    let paths = conn.paths();
    paths
        .iter()
        .find(iroh::endpoint::Path::is_selected)
        .or_else(|| paths.iter().next())
        .map(|p| p.rtt())
        .or_else(|| conn.rtt(PathId::ZERO))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_dir_is_xdg_then_home_and_never_elsewhere() {
        use std::ffi::OsString;
        use std::path::PathBuf;
        let s = |x: &str| Some(OsString::from(x));
        // $XDG_CONFIG_HOME wins outright.
        assert_eq!(
            config_dir_from(s("/x"), s("/home/u")),
            Some(PathBuf::from("/x/koh"))
        );
        // Else $HOME/.config/koh.
        assert_eq!(
            config_dir_from(None, s("/home/u")),
            Some(PathBuf::from("/home/u/.config/koh"))
        );
        // Empty values are skipped, not used.
        assert_eq!(
            config_dir_from(Some(OsString::new()), s("/home/u")),
            Some(PathBuf::from("/home/u/.config/koh"))
        );
        // No XDG and no HOME: NO default (the caller must pass --key-file) — koh never falls back to
        // a CWD/tmp/platform path. ~/.config is the only location koh ever picks on its own.
        assert_eq!(config_dir_from(None, None), None);
        assert_eq!(
            config_dir_from(Some(OsString::new()), Some(OsString::new())),
            None
        );
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(parse_endpoint_id("not-a-real-endpoint-id").is_err());
    }

    #[test]
    fn dns_spec_accepts_ip_and_ip_port_rejects_junk() {
        // Bare IPv4 defaults to :53; explicit port is honored.
        assert_eq!(
            parse_dns_spec("1.1.1.1"),
            Some(SocketAddr::from(([1, 1, 1, 1], 53)))
        );
        assert_eq!(
            parse_dns_spec("8.8.8.8:5353"),
            Some(SocketAddr::from(([8, 8, 8, 8], 5353)))
        );
        // IPv6 in both bare and bracketed-with-port forms.
        assert_eq!(
            parse_dns_spec("2001:4860:4860::8888").map(|a| a.port()),
            Some(53)
        );
        assert_eq!(
            parse_dns_spec("[2001:4860:4860::8888]:53").map(|a| a.port()),
            Some(53)
        );
        // Whitespace is tolerated; junk is rejected (no panic, no partial parse).
        assert_eq!(
            parse_dns_spec("  9.9.9.9  "),
            Some(SocketAddr::from(([9, 9, 9, 9], 53)))
        );
        assert_eq!(parse_dns_spec(""), None);
        assert_eq!(parse_dns_spec("not-an-ip"), None);
        assert_eq!(parse_dns_spec("8.8.8.8:"), None);
        assert_eq!(parse_dns_spec("8.8.8.8:99999"), None);
    }

    /// The exact iroh call the Android bare-id fix depends on: building a resolver from an
    /// explicit nameserver must succeed without reading (or panicking on) the host system DNS.
    /// Running this on the host verifies the API we can't compile-check on the Android target.
    #[test]
    fn explicit_nameserver_resolver_builds() {
        let _resolver =
            iroh::dns::DnsResolver::with_nameserver(SocketAddr::from(([8, 8, 8, 8], 53)));
    }

    /// Two real iroh endpoints on loopback connect and exchange a stream each way, under the
    /// per-role stream limits: no relay, no second machine, fully hermetic.
    #[test]
    fn two_endpoints_exchange_streams_over_loopback() {
        crate::test_runtime::current_thread().block_on(async {
            let server = bind_endpoint_local(generate_secret_key().expect("OS randomness"), true)
                .await
                .expect("bind server");
            let client = bind_endpoint_local(generate_secret_key().expect("OS randomness"), false)
                .await
                .expect("bind client");
            let server_addr = loopback_addr(&server);

            let srv = tokio::spawn(async move {
                let incoming = server.accept().await.expect("accept");
                let conn = incoming.await.expect("handshake");
                let mut recv = conn.accept_uni().await.expect("the client's stream");
                let ping = recv.read_to_end(64).await.expect("read ping");
                let mut send = conn.open_uni().await.expect("a server stream");
                send.write_all(&ping).await.expect("echo");
                send.finish().expect("finish");
                conn.closed().await;
            });

            let conn = client
                .connect(server_addr, ALPN)
                .await
                .expect("connect over loopback");
            let mut send = conn.open_uni().await.expect("open a stream");
            send.write_all(b"ping-over-real-iroh").await.expect("write");
            send.finish().expect("finish");
            let mut recv = conn.accept_uni().await.expect("the echo stream");
            let echoed = recv.read_to_end(64).await.expect("read the echo");
            assert_eq!(echoed, b"ping-over-real-iroh");

            conn.close(0u32.into(), b"done");
            let _ = srv.await;
        });
    }

    #[test]
    fn a_fixed_port_is_bound_and_a_taken_one_is_reported() {
        crate::test_runtime::current_thread().block_on(async {
            // A port the OS just handed out, so almost surely free.
            let port = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
                .and_then(|socket| socket.local_addr())
                .expect("a free port")
                .port();
            let secret = generate_secret_key().expect("OS randomness");
            let first = bind_on(secret.clone(), true, &Network::Local, Some(port))
                .await
                .expect("bind the port");
            let bound = first.bound_sockets();
            assert!(
                bound.iter().any(|s| s.is_ipv4() && s.port() == port),
                "{bound:?}"
            );
            assert!(
                bound
                    .iter()
                    .filter(|s| s.is_ipv6())
                    .all(|s| s.port() == port),
                "{bound:?}"
            );
            // The same port again, as a second server would: a clear error, not a random port.
            match bind_on(secret, true, &Network::Local, Some(port)).await {
                Err(SetupError::PortInUse(p)) => assert_eq!(p, port),
                Err(e) => panic!("expected PortInUse, got {e}"),
                Ok(_) => panic!("a taken port must not bind"),
            }
            assert_eq!(
                SetupError::PortInUse(port).to_string(),
                format!(
                    "UDP port {port} is already in use (another koh serve?); stop it or pick \
                     another --port"
                )
            );
            first.close().await;
        });
    }

    #[test]
    fn the_alpn_names_the_stream_protocol() {
        // `koh/3` is the stream protocol; a peer on another version (e.g. `koh/iroh/2`) fails the
        // TLS handshake instead of misparsing.
        assert_eq!(ALPN, b"koh/3");
    }
}
