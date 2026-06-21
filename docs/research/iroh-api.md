# iroh 1.0.0 — Ground-Truth API Cheat-Sheet (for a from-scratch Rust reimpl of mosh-over-iroh)

Source-of-truth: the actual crate sources under
`~/.cargo/registry/src/index.crates.io-*/iroh-1.0.0/` and `iroh-base-1.0.0/`,
plus the transport crate `noq-1.0.0` / `noq-proto-1.0.0` (a quinn fork; **this is
NOT quinn**, and `Connection`/streams are NOT re-exported quinn).

> **BIG VERSION-SPECIFIC SURPRISES — read these first**
> 1. **Renames vs. the iroh you remember.** `NodeId` → **`EndpointId`**, `NodeAddr` →
>    **`EndpointAddr`**, `node_id()` → **`id()`**, `node_addr()`/`Endpoint::node_addr` →
>    **`addr()`**, `Connection::remote_node_id()` → **`remote_id()`**. There is no
>    `NodeId`/`NodeAddr` type anymore.
> 2. **`Endpoint::builder` REQUIRES a `Preset` argument.** `Endpoint::builder(presets::N0)`.
>    There is no zero-arg `Endpoint::builder()`. A crypto provider is mandatory; the
>    preset supplies it.
> 3. **Transport is `noq`, not `quinn`.** All the QUIC types (`Connection`, `SendStream`,
>    `RecvStream`, `VarInt`, `ConnectionError`, `SendDatagramError`, …) are re-exported
>    from `noq` / `noq_proto` and re-exported again from `iroh::endpoint`.
> 4. **Datagrams are ON by default** (recv buffer defaults to `Some(STREAM_RWND)`, send
>    buffer `1 MiB`). No transport-config tweak is needed to use them.
> 5. **Errors use the `n0_error` framework** (`stack_error`), are `#[non_exhaustive]`, and
>    carry `add_meta`. Match with `..`.
> 6. `Connection` is generic: `Connection<State = HandshakeCompleted>`. The plain
>    `Connection` you normally hold is `Connection<HandshakeCompleted>`. 0-RTT gives you
>    `Connection<OutgoingZeroRtt>` / `Connection<IncomingZeroRtt>`.

---

## 0. Crate-level re-exports (`iroh::*`)

From `iroh/src/lib.rs`:

```rust
pub use endpoint::{Endpoint, RelayMode};
pub use iroh_base::{
    EndpointAddr, EndpointId, KeyParsingError, PublicKey, RelayUrl,
    RelayUrlParseError, SecretKey, Signature, SignatureError, TransportAddr,
};
pub use iroh_dns::dns;            // non-wasm
pub use iroh_dns::endpoint_info;
pub use iroh_relay::{RelayConfig, RelayMap};
pub use n0_watcher::Watcher;
pub use net_report::{NetReportConfig, TIMEOUT as NET_REPORT_TIMEOUT};

pub mod address_lookup;  // was "discovery"
pub mod defaults;
pub mod endpoint;
pub mod metrics;
pub mod protocol;
pub mod tls;
```

Public modules of note: `iroh::endpoint` (Endpoint, Builder, Connection, streams, quic
re-exports, `presets`), `iroh::protocol` (Router, ProtocolHandler), `iroh::address_lookup`
(the discovery system, formerly `discovery`).

`iroh::endpoint::presets` re-exported types: `Empty`, `Minimal`, `N0`, `N0DisableRelay`,
and the trait `Preset`.

---

## 1. Identity: SecretKey / PublicKey / EndpointId / EndpointAddr (`iroh_base`)

`iroh_base/src/lib.rs` (feature `key`):
```rust
pub use self::key::{EndpointId, KeyParsingError, PublicKey, SecretKey, Signature, SignatureError, SignatureParsingError};
pub use self::endpoint_addr::{CustomAddr, EndpointAddr, TransportAddr};
pub use self::relay_url::{RelayUrl, RelayUrlParseError};
```

### PublicKey / EndpointId
```rust
pub type EndpointId = PublicKey;     // identical types; EndpointId is the alias used for identity

#[repr(transparent)]
pub struct PublicKey(CompressedEdwardsY);   // Clone, Copy, PartialEq, Eq, Hash, Ord

impl PublicKey {
    pub const LENGTH: usize = 32;
    pub fn as_bytes(&self) -> &[u8; 32];
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, KeyParsingError>;  // validates curve point
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), SignatureError>;
    pub fn fmt_short(&self) -> impl Display + Copy + 'static;  // first 5 bytes, lowercase hex
    pub fn to_z32(&self) -> String;                            // z-base-32 (pkarr domain encoding)
    pub fn from_z32(s: &str) -> Result<Self, KeyParsingError>;
}
// Display / Debug: LOWERCASE HEX (64 chars). NOT z-base-32.
//   Display  -> "ae58ff88...".   Debug -> "PublicKey(ae58ff88...)"
// FromStr: accepts EITHER 64-char lowercase hex OR BASE32_NOPAD (uppercased internally).
impl FromStr for PublicKey { type Err = KeyParsingError; }
impl TryFrom<&[u8]>     for PublicKey { type Error = KeyParsingError; }
impl TryFrom<&[u8; 32]> for PublicKey { type Error = KeyParsingError; }
impl AsRef<[u8]> for PublicKey;  // Deref<Target=[u8;32]>, Borrow<[u8;32]>
// Serde: human-readable => hex string; binary => 32 raw bytes.
```
> Note: `to_string()`/`Display` is HEX, but `to_z32()` is z-base-32. `from_str` round-trips
> the `Display` (hex) and also the n0 base32 form. For the canonical mosh handle, use
> `id.to_string()` (hex) and parse back with `EndpointId::from_str`.

### SecretKey
```rust
#[derive(Clone, zeroize::ZeroizeOnDrop)]
pub struct SecretKey(SigningKey);   // Debug prints "SecretKey(..)"

impl SecretKey {
    pub fn public(&self) -> PublicKey;
    pub fn generate() -> Self;                 // uses rand::random() (the rand 0.9 default rng)
    pub fn sign(&self, msg: &[u8]) -> Signature;
    pub fn to_bytes(&self) -> [u8; 32];        // the secret scalar bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> Self;   // INFALLIBLE (unlike PublicKey::from_bytes)
}
impl From<[u8; 32]>  for SecretKey;
impl From<&[u8; 32]> for SecretKey;
impl TryFrom<&[u8]>  for SecretKey { type Error = KeyParsingError; }  // needs exactly 32 bytes
impl FromStr for SecretKey { type Err = KeyParsingError; }            // hex or base32
// Serde: serializes the inner SigningKey.
```
Generate from a custom RNG (rand 0.9 API; `RngExt::random`):
```rust
use rand::{RngExt, SeedableRng};
let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0);
let sk = SecretKey::from_bytes(&rng.random());   // <- canonical pattern in iroh's own tests
```
Persist / load: `let bytes: [u8;32] = sk.to_bytes();  let sk = SecretKey::from_bytes(&bytes);`

### Signature
```rust
pub struct Signature(ed25519_dalek::Signature);  // Copy
impl Signature {
    pub const LENGTH: usize = 64;
    pub fn to_bytes(&self) -> [u8; 64];
    pub fn from_bytes(bytes: &[u8; 64]) -> Self;
}
impl TryFrom<&[u8]> for Signature { type Error = SignatureParsingError; }
```

### EndpointAddr (was NodeAddr) + TransportAddr
```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EndpointAddr {
    pub id: EndpointId,                      // public field
    pub addrs: BTreeSet<TransportAddr>,      // public field
}
impl EndpointAddr {
    pub fn new(id: PublicKey) -> Self;                    // no addrs (relies on address-lookup)
    pub fn from_parts(id: PublicKey, addrs: impl IntoIterator<Item = TransportAddr>) -> Self;
    pub fn with_relay_url(self, relay_url: RelayUrl) -> Self;
    pub fn with_ip_addr(self, addr: SocketAddr) -> Self;
    pub fn with_addrs(self, addrs: impl IntoIterator<Item = TransportAddr>) -> Self;
    pub fn is_empty(&self) -> bool;
    pub fn ip_addrs(&self) -> impl Iterator<Item = &SocketAddr>;
    pub fn relay_urls(&self) -> impl Iterator<Item = &RelayUrl>;
}
impl From<EndpointId> for EndpointAddr;   // EndpointId -> EndpointAddr::new(id)

#[non_exhaustive]
pub enum TransportAddr {
    Relay(RelayUrl),
    Ip(SocketAddr),
    Custom(CustomAddr),
}
impl TransportAddr { pub fn is_relay(&self)->bool; pub fn is_ip(&self)->bool; pub fn is_custom(&self)->bool; }
```
> `EndpointAddr` is `Into<EndpointAddr>` from both itself and `EndpointId` — so
> `endpoint.connect(some_endpoint_id, alpn)` and `endpoint.connect(some_endpoint_addr, alpn)`
> both compile. For an IP-only direct connect:
> `EndpointAddr::new(id).with_ip_addr("1.2.3.4:5000".parse()?)`.

---

## 2. Endpoint construction (`iroh::endpoint`)

```rust
#[derive(Clone, Debug)]
pub struct Endpoint { /* Arc<EndpointInner> */ }

#[derive(Debug)]
pub struct Builder { /* see below */ }
```

### The Preset requirement (mandatory)
`Endpoint::builder` / `Endpoint::bind` take `impl Preset`. A preset must (at minimum) set a
`rustls::crypto::CryptoProvider`, otherwise `.bind()` fails with `BindError::InvalidCryptoProvider`.

```rust
pub trait Preset { fn apply(self, builder: Builder) -> Builder; }

// presets (in iroh::endpoint::presets):
presets::Empty           // sets nothing; bind() will FAIL (no crypto provider)
presets::Minimal         // ONLY sets the crypto provider (ring or aws-lc-rs). No relay, no discovery.
presets::N0              // Minimal + n0 DNS pkarr publish/resolve + default n0 relays
presets::N0DisableRelay  // N0 but RelayMode::Disabled
// Minimal/N0 require feature `tls-ring` or `tls-aws-lc-rs` (cfg `with_crypto_provider`).
```
For mosh-style p2p you almost certainly want **`presets::N0`** (relay + discovery so a bare
`EndpointId` is dialable) or **`presets::Minimal`** + manual `.relay_mode(...)`.

### Constructors
```rust
impl Endpoint {
    pub fn builder(preset: impl Preset) -> Builder;                       // Builder::new(preset)
    pub async fn bind(preset: impl Preset) -> Result<Self, BindError>;    // builder(preset).bind()
}
impl Builder {
    pub fn new(preset: impl Preset) -> Self;     // == empty().preset(preset)
    pub fn preset(self, preset: impl Preset) -> Self;
    pub fn empty() -> Self;                       // no discovery, RelayMode::Disabled, IPv4+IPv6 binds
    pub async fn bind(self) -> Result<Endpoint, BindError>;   // <- THE terminal call
}
```

### Builder methods you care about (exact signatures)
```rust
pub fn secret_key(self, secret_key: SecretKey) -> Self;   // persistent identity; else random
pub fn alpns(self, alpn_protocols: Vec<Vec<u8>>) -> Self;  // REQUIRED to accept() incoming
pub fn relay_mode(self, relay_mode: RelayMode) -> Self;
pub fn transport_config(self, transport_config: QuicTransportConfig) -> Self;
pub fn keylog(self, keylog: bool) -> Self;
pub fn crypto_provider(self, crypto_provider: Arc<rustls::crypto::CryptoProvider>) -> Self;
pub fn external_addr(self, addr: SocketAddr) -> Self;     // advertise a directly-reachable addr
pub fn ca_tls_config(self, ca_tls_config: CaTlsConfig) -> Self;   // for relays/DoH/pkarr (NOT iroh conns)
pub fn max_tls_tickets(self, n: usize) -> Self;           // default 256; bump for many-client 0-RTT
pub fn hooks(self, hooks: impl EndpointHooks + 'static) -> Self;
pub fn portmapper_config(self, config: PortmapperConfig) -> Self;  // default Enabled
pub fn net_report_config(self, config: NetReportConfig) -> Self;

// address-lookup (discovery) — replaces the old .discovery* methods
pub fn address_lookup(self, address_lookup: impl AddressLookupBuilder) -> Self;
pub fn clear_address_lookup(self) -> Self;
pub fn addr_filter(self, filter: AddrFilter) -> Self;
pub fn user_data_for_address_lookup(self, user_data: UserData) -> Self;

// socket binding (advanced; defaults bind 0.0.0.0 + [::])  [non-wasm]
pub fn bind_addr<A: ToSocketAddr>(self, addr: A) -> Result<Self, InvalidSocketAddr>
    where <A as ToSocketAddr>::Err: Into<InvalidSocketAddr>;
pub fn bind_addr_with_opts<A: ToSocketAddr>(self, addr: A, opts: BindOpts) -> Result<Self, InvalidSocketAddr> where ...;
pub fn clear_ip_transports(self) -> Self;
pub fn clear_relay_transports(self) -> Self;

// DNS / proxy
pub fn dns_resolver(self, dns_resolver: DnsResolver) -> Self;   // [non-wasm]
pub fn proxy_url(self, url: Url) -> Self;
pub fn proxy_from_env(self) -> Self;
```
> **No `discovery_n0()` / no `bind()` zero-arg.** The old `discovery_n0()` is now the
> behaviour baked into `presets::N0`. The old `discovery_dht`/`discovery_local_network` are now
> separate `AddressLookupBuilder` impls in `iroh::address_lookup` added via `.address_lookup(...)`.
> There is **no** `.discovery_n0()` builder method. To get n0 DNS discovery: use `presets::N0`,
> or `presets::Minimal` + `.address_lookup(PkarrPublisher::n0_dns())` +
> `.address_lookup(DnsAddressLookup::n0_dns())`.

### RelayMode
```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayMode { Disabled, Default, Staging, Custom(RelayMap) }
impl RelayMode {
    pub fn relay_map(&self) -> RelayMap;
    pub fn custom(map: impl IntoIterator<Item = RelayUrl>) -> Self;
}
pub fn default_relay_mode() -> RelayMode;   // Staging if IROH_FORCE_STAGING_RELAYS set, else Default
pub const ENV_FORCE_STAGING_RELAYS: &str = "IROH_FORCE_STAGING_RELAYS";
```

### Endpoint getters / identity
```rust
pub fn secret_key(&self) -> &SecretKey;
pub fn id(&self) -> EndpointId;                  // == secret_key.public()  (was node_id())
pub fn addr(&self) -> EndpointAddr;              // current relay+direct addrs (was node_addr())
pub fn watch_addr(&self) -> impl Watcher<Value = EndpointAddr> + use<>;
pub async fn online(&self);                      // resolves once >=1 home relay is connected
pub fn home_relay_status(&self) -> impl Watcher<Value = Vec<RelayStatus>> + use<>;
pub fn bound_sockets(&self) -> Vec<SocketAddr>;  // [non-wasm]
pub async fn remote_info(&self, endpoint_id: EndpointId) -> Option<RemoteInfo>;
pub fn metrics(&self) -> &EndpointMetrics;       // feature "metrics"

pub fn set_alpns(&self, alpns: Vec<Vec<u8>>);    // overrides accepted ALPNs at runtime
pub async fn add_external_addr(&self, addr: SocketAddr);
pub async fn network_change(&self);

pub async fn close(&self);                        // graceful; awaits peer close-acks
pub fn is_closed(&self) -> bool;
pub fn closed(&self) -> EndpointClosed;           // future; EndpointClosed::run_until(fut)
```

### BindError
`pub use crate::socket::BindError;` — `#[non_exhaustive]`, `n0_error` enum. Relevant variants seen
in source: `BindError::InvalidCryptoProvider`, `BindError::InvalidCaRootConfig`. Treat as opaque +
match `..`.

### Minimal happy-path bind
```rust
use iroh::{Endpoint, endpoint::presets};

let ep = Endpoint::builder(presets::N0)
    .secret_key(my_secret_key)            // persistent identity (optional)
    .alpns(vec![b"mosh/iroh/1".to_vec()]) // only needed on the side that accept()s
    .bind()
    .await?;                              // Result<Endpoint, BindError>
let my_id = ep.id();                      // EndpointId — share this string with the client
```

---

## 3. Connecting (client side)

```rust
pub async fn connect(
    &self,
    endpoint_addr: impl Into<EndpointAddr>,   // EndpointId OR EndpointAddr
    alpn: &[u8],                              // ALPN is &[u8]
) -> Result<Connection, ConnectError>;       // Connection == Connection<HandshakeCompleted>

pub async fn connect_with_opts(
    &self,
    endpoint_addr: impl Into<EndpointAddr>,
    alpn: &[u8],
    options: ConnectOptions,
) -> Result<Connecting, ConnectWithOptsError>;   // await the Connecting, or .into_0rtt()
```
- Target type: **`impl Into<EndpointAddr>`** → pass an `EndpointId` (auto-converts) or a full
  `EndpointAddr`. With `presets::N0` a bare `EndpointId` is enough (DNS discovery resolves it).
  Without discovery you must pass an `EndpointAddr` carrying a relay URL and/or direct IPs.
- ALPN: `&[u8]`.
- Connecting to your own id errors with `ConnectWithOptsError::SelfConnect`.

```rust
#[derive(Default, Debug, Clone)]
pub struct ConnectOptions { /* private */ }
impl ConnectOptions {
    pub fn new() -> Self;
    pub fn with_transport_config(self, transport_config: QuicTransportConfig) -> Self;
    pub fn with_additional_alpns(self, alpns: Vec<Vec<u8>>) -> Self;
}

#[non_exhaustive] pub enum ConnectError {
    Connect { source: ConnectWithOptsError },
    Connecting { source: ConnectingError },
    Connection { source: ConnectionError },
}
#[non_exhaustive] pub enum ConnectWithOptsError {
    SelfConnect, NoAddress{..}, Noq{..}, InternalConsistencyError{..},
    LocallyRejected, EndpointClosed,
}
```

`Connecting` (outgoing handshake-in-progress future):
```rust
pub struct Connecting { /* private */ }
impl Connecting {
    pub fn into_0rtt(self) -> Result<OutgoingZeroRttConnection, Connecting>; // Err = couldn't even try
    pub async fn handshake_data(&mut self) -> Result<Box<dyn Any>, ConnectionError>;
    pub async fn alpn(&mut self) -> Result<Vec<u8>, AlpnError>;
    pub fn remote_id(&self) -> EndpointId;
}
impl Future for Connecting { type Output = Result<Connection, ConnectingError>; }
```

### Connect happy path
```rust
let conn = ep.connect(server_id, b"mosh/iroh/1").await?;  // server_id: EndpointId
```

---

## 4. Accepting (server side)

Two ways: raw `Endpoint::accept()` loop, or the `protocol::Router`.

### 4a. Raw accept loop
```rust
pub fn accept(&self) -> Accept<'_>;     // a future
impl Future for Accept<'_> { type Output = Option<Incoming>; }   // None => endpoint closed
```
`Incoming` — pre-handshake; cheap to inspect/reject:
```rust
pub struct Incoming { /* private */ }
impl Incoming {
    pub fn accept(self) -> Result<Accepting, ConnectionError>;
    pub fn accept_with(self, server_config: Arc<ServerConfig>) -> Result<Accepting, ConnectionError>;
    pub fn refuse(self);
    pub fn retry(self) -> Result<(), RetryError>;   // address-validation challenge
    pub fn ignore(self);
    pub fn local_addr(&self) -> LocalTransportAddr;
    pub fn remote_addr(&self) -> IncomingAddr;       // enum: Ip(SocketAddr) | Relay{url,endpoint_id} | Custom
    pub fn remote_addr_validated(&self) -> bool;
    pub fn decrypt(&self) -> Option<DecryptedInitial>;  // peek ClientHello (~1200B, costly)
}
// Incoming is ALSO awaitable directly:
impl IntoFuture for Incoming { type Output = Result<Connection, ConnectingError>; }
```
`Accepting` — post-`accept()`, handshake in progress:
```rust
pub struct Accepting { /* private */ }
impl Accepting {
    pub fn into_0rtt(self) -> IncomingZeroRttConnection;        // always succeeds (0.5-RTT if no client 0-RTT)
    pub fn remote_addr(&self) -> IncomingAddr;
    pub async fn handshake_data(&mut self) -> Result<Box<dyn Any>, ConnectionError>;
    pub async fn alpn(&mut self) -> Result<Vec<u8>, AlpnError>;   // <- read negotiated ALPN before full conn
}
impl Future for Accepting { type Output = Result<Connection, ConnectingError>; }
```

Raw-accept happy path (mirrors iroh's own tests):
```rust
let incoming = ep.accept().await.ok_or("endpoint closed")?;   // Option<Incoming>
let conn = incoming.await?;                                    // Result<Connection, ConnectingError>
let remote = conn.remote_id();                                // EndpointId of the peer
let alpn = conn.alpn();                                        // &[u8]
```
Or to gate on ALPN before committing:
```rust
let mut accepting = incoming.accept()?;            // Result<Accepting, ConnectionError>
let alpn: Vec<u8> = accepting.alpn().await?;        // negotiated ALPN
if alpn == b"mosh/iroh/1" { let conn = accepting.await?; /* ... */ }
```

### 4b. Router + ProtocolHandler (`iroh::protocol`)
```rust
#[derive(Clone, Debug)] pub struct Router { /* private */ }
impl Router {
    pub fn builder(endpoint: Endpoint) -> RouterBuilder;
    pub fn endpoint(&self) -> &Endpoint;
    pub fn is_shutdown(&self) -> bool;
    pub async fn shutdown(&self) -> Result<(), n0_future::task::JoinError>;
}
pub struct RouterBuilder { /* private */ }
impl RouterBuilder {
    pub fn new(endpoint: Endpoint) -> Self;
    pub fn accept(self, alpn: impl AsRef<[u8]>, handler: impl Into<Box<dyn DynProtocolHandler>>) -> Self;
    pub fn incoming_filter(self, filter: IncomingFilter) -> Self;
    pub fn endpoint(&self) -> &Endpoint;
    #[must_use] pub fn spawn(self) -> Router;     // <- spawns accept loop; ALSO calls ep.set_alpns(...)
}
```
> `spawn()` auto-registers the handlers' ALPNs onto the endpoint (`self.endpoint.set_alpns(alpns)`),
> so you do NOT need `.alpns(...)` on the builder when you use a Router. Keep the `Router` value
> alive — it aborts the accept loop on drop.

```rust
pub trait ProtocolHandler: Send + Sync + std::fmt::Debug + 'static {
    // REQUIRED:
    fn accept(&self, connection: Connection)
        -> impl Future<Output = Result<(), AcceptError>> + Send;
    // OPTIONAL (defaults provided):
    fn on_accepting(&self, accepting: Accepting)
        -> impl Future<Output = Result<Connection, AcceptError>> + Send { /* default: accepting.await */ }
    fn shutdown(&self) -> impl Future<Output = ()> + Send { /* default: noop */ }
}
// Implemented for Arc<T> and Box<T> where T: ProtocolHandler.
// Any ProtocolHandler also auto-implements the dyn-friendly DynProtocolHandler,
//   and `impl From<T: ProtocolHandler> for Box<dyn DynProtocolHandler>` exists.

#[non_exhaustive] pub enum AcceptError {
    Connecting { source: ConnectingError },
    Connection { source: ConnectionError },
    MissingRemoteEndpointId { source: RemoteEndpointIdError },
    NotAllowed {},
    User { source: AnyError },
}
impl AcceptError {
    pub fn from_err<T: std::error::Error + Send + Sync + 'static>(value: T) -> Self;
    pub fn from_boxed(value: Box<dyn std::error::Error + Send + Sync>) -> Self;
}
// From<std::io::Error> and From<ClosedStream> exist.

#[non_exhaustive] pub enum IncomingFilterOutcome { Accept, Retry, Reject, Ignore }
pub type IncomingFilter = Arc<dyn Fn(&Incoming) -> IncomingFilterOutcome + Send + Sync + 'static>;
```
Router happy path (the canonical echo example, verbatim shape from source):
```rust
use iroh::{Endpoint, endpoint::{Connection, presets}, protocol::{AcceptError, ProtocolHandler, Router}};

#[derive(Debug, Clone)]
struct Echo;
impl ProtocolHandler for Echo {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let (mut send, mut recv) = connection.accept_bi().await?;
        tokio::io::copy(&mut recv, &mut send).await?;   // AsyncRead/AsyncWrite impls exist
        send.finish()?;
        connection.closed().await;
        Ok(())
    }
}

let endpoint = Endpoint::bind(presets::N0).await?;
let router = Router::builder(endpoint).accept(b"mosh/iroh/1", Echo).spawn();
// ... keep `router` alive ...
router.shutdown().await?;
```

---

## 5. Connection — streams, datagrams, RTT/stats, identity (`iroh::endpoint::Connection`)

`Connection` wraps a `noq::Connection` (NOT quinn). It is generic over a state marker:
```rust
#[derive(Debug, Clone)]
pub struct Connection<State: ConnectionState = HandshakeCompleted> { /* private */ }
// markers: HandshakeCompleted (default), IncomingZeroRtt, OutgoingZeroRtt
pub type OutgoingZeroRttConnection = Connection<OutgoingZeroRtt>;
pub type IncomingZeroRttConnection = Connection<IncomingZeroRtt>;
```
`Connection` is `Clone` (another handle to the same conn). If ALL handles + all stream objects
drop, the conn auto-closes (code 0, empty reason).

### 5a. Methods on ALL states (`impl<T: ConnectionState> Connection<T>`)
```rust
// --- streams (return noq stream-opening futures) ---
pub fn open_uni(&self)   -> OpenUni<'_>;     // .await -> Result<SendStream, ConnectionError>
pub fn open_bi(&self)    -> OpenBi<'_>;      // .await -> Result<(SendStream, RecvStream), ConnectionError>
pub fn accept_uni(&self) -> AcceptUni<'_>;   // .await -> Result<RecvStream, ConnectionError>
pub fn accept_bi(&self)  -> AcceptBi<'_>;    // .await -> Result<(SendStream, RecvStream), ConnectionError>

// --- datagrams ---
pub fn send_datagram(&self, data: bytes::Bytes) -> Result<(), SendDatagramError>;
pub fn send_datagram_wait(&self, data: bytes::Bytes) -> SendDatagram<'_>;   // .await; waits on congestion
pub fn read_datagram(&self) -> ReadDatagram<'_>;   // .await -> Result<bytes::Bytes, ConnectionError>
pub fn max_datagram_size(&self) -> Option<usize>;  // None if peer unsupported OR locally disabled
pub fn datagram_send_buffer_space(&self) -> usize;

// --- lifecycle ---
pub async fn closed(&self) -> ConnectionError;     // resolves when conn closes (reason)
pub fn close_reason(&self) -> Option<ConnectionError>;
pub fn close(&self, error_code: VarInt, reason: &[u8]);   // immediate close

// --- rtt / stats ---
pub fn rtt(&self, path_id: PathId) -> Option<Duration>;   // per-path RTT; None if no such path
pub fn stats(&self) -> ConnectionStats;                   // aggregate over all paths (see below)
pub fn congestion_state(&self, path_id: PathId) -> Option<Box<dyn Controller>>;

// --- crypto / identity (generic) ---
pub fn handshake_data(&self) -> Option<Box<dyn Any>>;
pub fn peer_identity(&self) -> Option<Box<dyn Any>>;   // downcast to Vec<rustls::pki_types::CertificateDer>
pub fn stable_id(&self) -> usize;
pub fn export_keying_material(&self, output: &mut [u8], label: &[u8], context: &[u8])
    -> Result<(), ExportKeyingMaterialError>;

// --- flow control tuning ---
pub fn set_max_concurrent_uni_streams(&self, count: VarInt);
pub fn set_max_concurrent_bi_streams(&self, count: VarInt);
pub fn set_receive_window(&self, receive_window: VarInt);
```

### 5b. Methods ONLY on `Connection<HandshakeCompleted>` (the normal case)
```rust
pub fn alpn(&self) -> &[u8];               // negotiated ALPN, cheap (cached) — INFALLIBLE here
pub fn remote_id(&self) -> EndpointId;     // peer's EndpointId — INFALLIBLE here (was remote_node_id())
pub fn side(&self) -> Side;                // Client | Server
pub fn weak_handle(&self) -> WeakConnectionHandle;

// path observation (relay path + direct path after holepunch)
pub fn paths(&self) -> PathList<'_>;            // snapshot; .iter() -> PathListIter -> Path<'_>
pub fn paths_stream(&self) -> PathListStream<'_>;   // Stream<Item = PathList<'_>>; borrows conn
pub fn path_events(&self) -> PathEventStream;       // Stream<Item = PathEvent>; 'static, movable
```
> On the 0-RTT marker types, `alpn()` returns `Option<Vec<u8>>` and `remote_id()` returns
> `Result<EndpointId, RemoteEndpointIdError>` (handshake may not be done yet). After
> `handshake_completed().await?` you get a normal `Connection<HandshakeCompleted>`.

### 5c. RTT — exact path
- Quick aggregate: `conn.stats()` → `ConnectionStats` (fields below) — **but note: aggregate
  `ConnectionStats` does NOT include rtt/cwnd/mtu** (those are dropped when summing paths).
- For real RTT, iterate paths:
```rust
for path in conn.paths().iter() {           // path: iroh::endpoint::Path<'_>
    let rtt: Duration   = path.rtt();        // == path.stats().rtt
    let st:  PathStats  = path.stats();
    let id:  PathId     = path.id();
    let selected        = path.is_selected();
    let _ = (path.is_ip(), path.is_relay(), path.remote_addr());
}
// or, if you cached a PathId:  let rtt: Option<Duration> = conn.rtt(path_id);
```
`iroh::endpoint::Path<'a>` methods:
```rust
pub fn id(&self) -> PathId;
pub fn remote_addr(&self) -> &TransportAddr;
pub fn local_addr(&self) -> &LocalTransportAddr;
pub fn is_selected(&self) -> bool;
pub fn is_ip(&self) -> bool;
pub fn is_relay(&self) -> bool;
pub fn stats(&self) -> PathStats;
pub fn rtt(&self) -> Duration;
```
`PathList<'_>`: `pub fn len(&self)->usize; pub fn is_empty(&self)->bool; pub fn iter(&self)->PathListIter<'_>;`

### 5d. Stats structs (from `noq_proto`, re-exported as `iroh::endpoint::{ConnectionStats, PathStats, FrameStats, UdpStats}`)
```rust
#[non_exhaustive] #[derive(Debug, Default, Clone)]
pub struct ConnectionStats {   // SUM over all paths; rtt/cwnd/mtu intentionally omitted
    pub udp_tx: UdpStats, pub udp_rx: UdpStats,
    pub frame_tx: FrameStats, pub frame_rx: FrameStats,
    pub lost_packets: u64, pub lost_bytes: u64,
}
#[non_exhaustive] #[derive(Debug, Default, Copy, Clone, ...)]
pub struct PathStats {         // PER PATH — this is where rtt/cwnd/mtu live
    pub rtt: Duration,
    pub udp_tx: UdpStats, pub udp_rx: UdpStats,
    pub frame_tx: FrameStats, pub frame_rx: FrameStats,
    pub cwnd: u64,
    pub congestion_events: u64, pub spurious_congestion_events: u64,
    pub lost_packets: u64, pub lost_bytes: u64,
    pub sent_plpmtud_probes: u64, pub lost_plpmtud_probes: u64,
    pub black_holes_detected: u64,
    pub current_mtu: u16,
}
#[non_exhaustive] #[derive(Default, Copy, Clone, ...)]
pub struct UdpStats { pub datagrams: u64, pub bytes: u64, pub ios: u64 }
#[non_exhaustive] pub struct FrameStats { /* per-frame-type counters incl. `pub datagram: u64` */ }
```

### 5e. SendDatagramError (from `noq_proto`)
```rust
#[non_exhaustive] pub enum SendDatagramError {
    UnsupportedByPeer,   // peer didn't advertise max_datagram_frame_size
    Disabled,            // local datagram support off (recv buffer set to None)
    TooLarge,            // exceeds current path MTU minus overhead / peer limit
    Blocked(bytes::Bytes),  // send-buffer full; returns your bytes back (only from send_datagram, not _wait)
}
```

### 5f. noq stream types (`iroh::endpoint::{SendStream, RecvStream}`)
Both impl `tokio::io::AsyncWrite`/`AsyncRead` and `futures_io` equivalents (so `tokio::io::copy`,
`AsyncReadExt`, `AsyncWriteExt` all work). Inherent methods:
```rust
pub struct SendStream { /* noq */ }
impl SendStream {
    pub async fn write(&mut self, buf: &[u8]) -> Result<usize, WriteError>;
    pub async fn write_all(&mut self, buf: &[u8]) -> Result<(), WriteError>;
    pub async fn write_chunk(&mut self, buf: bytes::Bytes) -> Result<(), WriteError>;
    pub async fn write_all_chunks(&mut self, bufs: &mut [bytes::Bytes]) -> Result<(), WriteError>;
    pub fn finish(&mut self) -> Result<(), ClosedStream>;      // NOTE: sync, returns Result
    pub fn reset(&mut self, error_code: VarInt) -> Result<(), ClosedStream>;
    pub fn set_priority(&self, priority: i32) -> Result<(), ClosedStream>;
    pub fn priority(&self) -> Result<i32, ClosedStream>;
    pub fn stopped(&self) -> Stopped;     // .await
    pub fn id(&self) -> StreamId;
}

pub struct RecvStream { /* noq */ }
impl RecvStream {
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<Option<usize>, ReadError>;  // None = stream end
    pub async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), ReadExactError>;
    pub async fn read_chunk(&mut self, max_length: usize) -> Result<Option<bytes::Bytes>, ReadError>;
    pub async fn read_to_end(&mut self, size_limit: usize) -> Result<Vec<u8>, ReadToEndError>;
    pub fn stop(&mut self, error_code: VarInt) -> Result<(), ClosedStream>;
    pub fn is_0rtt(&self) -> bool;
    pub fn id(&self) -> StreamId;
    pub fn bytes_read(&self) -> Result<u64, ClosedStream>;
    pub async fn received_reset(&mut self) -> Result<Option<VarInt>, ResetError>;
    pub fn into_unordered(self) -> UnorderedRecvStream;
}
```
> **`SendStream::finish()` is synchronous and returns `Result<(), ClosedStream>`** — do NOT
> `.await` it. (Common mistake migrating from older quinn-based code.)

### 5g. ConnectionError / VarInt / ApplicationClose
```rust
pub use noq::ConnectionError;        // iroh::endpoint::ConnectionError
// variants you'll match: ConnectionError::LocallyClosed,
//   ConnectionError::ApplicationClosed(ApplicationClose { error_code: VarInt, reason: Bytes }), ...
pub struct ApplicationClose { pub error_code: VarInt, pub reason: bytes::Bytes }  // noq_proto

pub struct VarInt(/* u64 */);   // iroh::endpoint::VarInt (from noq_proto)
impl VarInt {
    pub const MAX: Self = /* (1<<62)-1 */;
    pub const fn from_u32(x: u32) -> Self;
    pub fn from_u64(x: u64) -> Result<Self, VarIntBoundsExceeded>;
    pub const fn into_inner(self) -> u64;
}
impl From<u8>  for VarInt;
impl From<u16> for VarInt;
impl From<u32> for VarInt;
// => idiomatic close: conn.close(0u32.into(), b"bye");   // From<u32>
```
`PathId` (from `noq_proto`, re-exported as `iroh::endpoint::PathId`):
```rust
pub struct PathId(/* u32 */);   // Copy, Ord, Hash, Default
impl PathId { pub const ZERO: Self = PathId(0); }   // no public u32 constructor; obtain via Path::id()/PathStats
```

---

## 6. Datagrams: enabled by default + the max_datagram_frame_size knob

**Datagrams are enabled by default — no config change needed.** From `noq_proto`'s default
`TransportConfig` (`config/transport.rs`):
```text
datagram_receive_buffer_size: Some(STREAM_RWND as usize)   // enabled
datagram_send_buffer_size:    1024 * 1024                  // 1 MiB
```
The advertised `max_datagram_frame_size` transport parameter is **derived** from the receive
buffer (`transport_parameters.rs`):
```text
max_datagram_frame_size = datagram_receive_buffer_size.map(|x| (x.min(u16::MAX) as u16).into())
```
So:
- To **keep datagrams on** (default): do nothing.
- To **disable receiving** datagrams (and thus advertise none): set the recv buffer to `None`.
- There is **no direct `max_datagram_frame_size(...)` setter** on the iroh builder; you control
  it indirectly via `datagram_receive_buffer_size`.

Reach it from the iroh builder via `QuicTransportConfig`:
```rust
use iroh::endpoint::{QuicTransportConfig, presets, Endpoint};

let tc = QuicTransportConfig::builder()
    .datagram_receive_buffer_size(Some(256 * 1024))   // Option<usize>; None disables RX (and advertised frame size)
    .datagram_send_buffer_size(1024 * 1024)           // usize
    .build();                                          // -> QuicTransportConfig

let ep = Endpoint::builder(presets::N0)
    .transport_config(tc)                              // Builder::transport_config(QuicTransportConfig)
    .alpns(vec![b"mosh/iroh/1".to_vec()])
    .bind()
    .await?;
```
`QuicTransportConfig` / builder (newtypes over `noq::TransportConfig`):
```rust
pub struct QuicTransportConfig(/* Arc<noq::TransportConfig> */);  // Default impl present
impl QuicTransportConfig { pub fn builder() -> QuicTransportConfigBuilder; }

pub struct QuicTransportConfigBuilder(/* noq::TransportConfig */);
impl QuicTransportConfigBuilder {
    pub fn new() -> Self;
    pub fn build(self) -> QuicTransportConfig;
    pub fn datagram_receive_buffer_size(self, value: Option<usize>) -> Self;  // None disables datagrams
    pub fn datagram_send_buffer_size(self, value: usize) -> Self;
    pub fn max_concurrent_bidi_streams(self, value: VarInt) -> Self;
    pub fn max_concurrent_uni_streams(self, value: VarInt) -> Self;
    pub fn max_idle_timeout(self, value: Option<IdleTimeout>) -> Self;   // see below
    pub fn keep_alive_interval(self, value: Duration) -> Self;
    pub fn initial_rtt(self, value: Duration) -> Self;
    pub fn stream_receive_window(self, value: VarInt) -> Self;
    pub fn receive_window(self, value: VarInt) -> Self;
    pub fn send_window(self, value: u64) -> Self;
    pub fn initial_mtu(self, value: u16) -> Self;
    pub fn min_mtu(self, value: u16) -> Self;
    pub fn mtu_discovery_config(self, value: Option<MtuDiscoveryConfig>) -> Self;
    pub fn ack_frequency_config(self, value: Option<AckFrequencyConfig>) -> Self;
    pub fn congestion_controller_factory(self, factory: Arc<dyn ControllerFactory + Send + Sync>) -> Self;
    // ... plus pad_to_mtu, allow_spin, send_fairness, packet_threshold, time_threshold,
    //     persistent_congestion_threshold, crypto_buffer_size, multipath knobs, qlog_* ...
}
```
Idle-timeout idiom (note the `VarInt` → `IdleTimeout` conversion):
```rust
let tc = QuicTransportConfig::builder()
    .max_idle_timeout(Some(VarInt::from_u32(10_000).into()))   // 10s as ms; Some(...)/None to disable
    .keep_alive_interval(std::time::Duration::from_secs(5))
    .build();
```

For mosh (latency-sensitive, unreliable input/output frames), datagrams are the natural fit and
are on by default. Use `conn.send_datagram(Bytes)` for the unreliable path and a single bi-stream
for reliable control. Watch `conn.max_datagram_size() -> Option<usize>` to size frames; it changes
with path MTU.

---

## 7. End-to-end minimal compiling happy-path (both sides)

```rust
use iroh::{Endpoint, EndpointId, endpoint::presets};
use n0_error::Result;

// ---------- SERVER ----------
async fn server(secret: iroh::SecretKey) -> Result<()> {
    let ep = Endpoint::builder(presets::N0)
        .secret_key(secret)
        .alpns(vec![b"mosh/iroh/1".to_vec()])
        .bind()
        .await?;
    println!("server id = {}", ep.id());      // hex string to hand to the client

    while let Some(incoming) = ep.accept().await {   // Option<Incoming>; None => closed
        let conn = match incoming.await {            // Result<Connection, ConnectingError>
            Ok(c) => c,
            Err(e) => { eprintln!("accept failed: {e:#}"); continue; }
        };
        let _peer: EndpointId = conn.remote_id();
        tokio::spawn(async move {
            // reliable control stream
            let (mut send, mut recv) = conn.accept_bi().await?;
            let buf = recv.read_to_end(64 * 1024).await?;
            send.write_all(&buf).await?;
            send.finish()?;                          // sync, returns Result
            // unreliable datagrams
            while let Ok(dgram) = conn.read_datagram().await {
                conn.send_datagram(dgram).ok();      // echo; ignores SendDatagramError
            }
            conn.closed().await;
            n0_error::Ok(())
        });
    }
    ep.close().await;
    Ok(())
}

// ---------- CLIENT ----------
async fn client(server_id: EndpointId) -> Result<()> {
    let ep = Endpoint::bind(presets::N0).await?;     // random identity; N0 => bare id is dialable
    let conn = ep.connect(server_id, b"mosh/iroh/1").await?;   // Into<EndpointAddr> from EndpointId

    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(b"hello").await?;
    send.finish()?;
    let _echo = recv.read_to_end(64 * 1024).await?;

    if let Some(max) = conn.max_datagram_size() {
        let _ = max;
        conn.send_datagram(bytes::Bytes::from_static(b"ping"))?;  // datagrams on by default
        let _pong = conn.read_datagram().await?;
    }

    // RTT of the currently-selected path:
    if let Some(p) = conn.paths().iter().find(|p| p.is_selected()) {
        println!("rtt = {:?}", p.rtt());
    }

    conn.close(0u32.into(), b"bye");                 // VarInt via From<u32>
    ep.close().await;
    Ok(())
}
```

---

## 8. Quick gotcha checklist for the reimplementation

- `Endpoint::builder(preset)` / `Endpoint::bind(preset)` — preset is **mandatory**; pick `presets::N0`.
- Identity getter is `ep.id()` (not `node_id()`); addr getter is `ep.addr()` (not `node_addr()`).
- `connect(target, alpn)`: `target: impl Into<EndpointAddr>` (so `EndpointId` works), `alpn: &[u8]`.
- `accept()` returns `Accept<'_>` → `Option<Incoming>`; `Incoming` is awaitable (→ `Connection`)
  or `incoming.accept()?` → `Accepting` (await for `Connection`, inspect ALPN via `accepting.alpn().await`).
- `Connection::remote_id() -> EndpointId`, `Connection::alpn() -> &[u8]` (both infallible on
  `HandshakeCompleted`).
- `SendStream::finish()` is **sync**, returns `Result<(), ClosedStream>`.
- Datagrams: on by default; `send_datagram(Bytes) -> Result<(), SendDatagramError>`,
  `read_datagram() -> ReadDatagram (await -> Result<Bytes, ConnectionError>)`,
  `max_datagram_size() -> Option<usize>`. Disable by setting `datagram_receive_buffer_size(None)`.
- RTT lives in `PathStats.rtt` (per-path), reachable via `conn.paths().iter()` →
  `Path::rtt()`/`Path::stats()`, or `conn.rtt(path_id)`. Aggregate `conn.stats()` deliberately
  excludes rtt/cwnd/mtu.
- Transport is `noq`; do NOT import or expect `quinn`. All QUIC types come from
  `iroh::endpoint::*` (which re-exports `noq`/`noq_proto`).
- Errors are `n0_error` `#[non_exhaustive]` enums; match with `..` and convert with the provided
  `from_err`/`StdResultExt`/`StackResultExt` helpers (n0_error crate).
- `close(code, reason)` takes `VarInt` (use `0u32.into()`), and graceful `Endpoint::close().await`
  should be awaited before exit to flush close frames.
```
