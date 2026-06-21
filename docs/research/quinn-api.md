# quinn / quinn-proto / iroh(noq) datagram + stream + stats API cheat-sheet

Ground-truth extracted from actual source. Read against these exact files:

- `quinn-0.11.9/src/connection.rs`, `send_stream.rs`, `recv_stream.rs`
- `quinn-proto-0.11.14/src/connection/stats.rs`, `connection/datagrams.rs`, `config/transport.rs`
- `iroh-1.0.0/src/endpoint/connection.rs`, `endpoint/quic.rs`
- `noq-1.0.0/src/connection.rs`, `send_stream.rs`, `recv_stream.rs`
- `noq-proto-1.0.0/src/connection/stats.rs`, `connection/paths.rs`

---

## CRITICAL: iroh 1.0.0 does NOT use upstream quinn. It uses a fork called `noq`.

The project's `Cargo.toml` lists both `quinn = "0.11.9"` and `iroh = "1.0.0"`, but they are
**two independent QUIC stacks**:

- `quinn` 0.11.9 / `quinn-proto` 0.11.14 = upstream. Single-path. `ConnectionStats` contains a
  `path: PathStats` field. `Connection::rtt()` takes no args.
- `iroh::endpoint::Connection` wraps `noq::Connection` (`noq` 1.0.0 / `noq-proto` 1.0.0), a
  **multipath** fork. iroh re-exports `noq`/`noq_proto` types from `iroh::endpoint::quic` under
  the same public names (`ConnectionStats`, `PathStats`, `SendDatagramError`, `SendStream`, ...).
  These types are NOT the upstream quinn types and have **different fields/signatures**.

When coding against iroh, use the iroh/noq shapes below (sections "NOQ / IROH"). The upstream
quinn shapes (sections "QUINN UPSTREAM") are documented for completeness / if you ever talk to
raw quinn. The two are wire-compatible-ish but source-incompatible.

Key divergences (iroh/noq vs upstream quinn):

| API | upstream quinn 0.11.9 | iroh / noq 1.0.0 |
|---|---|---|
| `Connection::rtt` | `fn rtt(&self) -> Duration` | `fn rtt(&self, path_id: PathId) -> Option<Duration>` |
| `Connection::stats` | `-> ConnectionStats` (has `.path: PathStats`) | `-> ConnectionStats` (NO `path` field; has `lost_packets`/`lost_bytes`) |
| per-path stats | `stats().path` | `path_stats(&self, path_id: PathId) -> Option<PathStats>` |
| `Connection::congestion_state` | `-> Box<dyn Controller>` | `fn congestion_state(&self, path_id: PathId) -> Option<Box<dyn Controller>>` |
| `ConnectionStats` rtt/cwnd/mtu | in `.path` | NOT in `ConnectionStats`; only in per-path `PathStats` |
| `iroh::endpoint::Connection` | n/a | generic: `Connection<State: ConnectionState = HandshakeCompleted>` |

For mosh-style single-path use, the default/only path is `PathId::ZERO`.

---

# NOQ / IROH (this is what you code against through `iroh`)

All these are re-exported from `iroh::endpoint` (see `iroh-1.0.0/src/endpoint/quic.rs` and the
`pub use` block in `endpoint.rs`). `iroh::endpoint::Connection` is a thin generic wrapper whose
methods all `#[inline]` delegate to the inner `noq::Connection`; signatures are identical to the
noq ones below.

## iroh::endpoint::Connection (wrapper)

```rust
pub struct Connection<State: ConnectionState = HandshakeCompleted> { /* inner: noq::Connection */ }
// You almost always have `Connection` (== Connection<HandshakeCompleted>) from connect()/accept().
```

## Datagrams (noq::Connection, identical via iroh)

```rust
// Enqueue an unreliable datagram. Drops oldest queued unsent datagrams to make room. Non-blocking.
pub fn send_datagram(&self, data: bytes::Bytes) -> Result<(), SendDatagramError>;

// Like send_datagram but waits for buffer space (prioritizes old over new). Returns a Future.
pub fn send_datagram_wait(&self, data: bytes::Bytes) -> SendDatagram<'_>;
//   impl Future for SendDatagram<'_> { type Output = Result<(), SendDatagramError>; }

// Receive one datagram. Returns a Future.
pub fn read_datagram(&self) -> ReadDatagram<'_>;
//   impl Future for ReadDatagram<'_> { type Output = Result<bytes::Bytes, ConnectionError>; }

// Max payload you may pass to send_datagram. None => peer unsupported or locally disabled.
// Varies with path MTU over connection lifetime. ">= ~1KB" guaranteed if peer limit is large.
pub fn max_datagram_size(&self) -> Option<usize>;

// Bytes free in outgoing datagram buffer. > 0 => a datagram this size won't evict older ones.
pub fn datagram_send_buffer_space(&self) -> usize;
```

### SendDatagramError (noq, re-exported as `iroh::endpoint::SendDatagramError`)
`noq-1.0.0/src/connection.rs:1881`
```rust
#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum SendDatagramError {
    UnsupportedByPeer,                       // "datagrams not supported by peer"
    Disabled,                                // "datagram support disabled"
    TooLarge,                                // "datagram too large" (path MTU - overhead, or peer limit, exceeded)
    ConnectionLost(#[from] ConnectionError), // "connection lost"
}
```
Note: the proto-level `Blocked(Bytes)` variant is never surfaced by `send_datagram` (it passes
`drop=true` so `Blocked` is `unreachable!()`). `send_datagram_wait` internally handles `Blocked`
by waiting; it also never returns a `Blocked` variant (this public enum has none).

## Stats / RTT (noq — MULTIPATH, differs from upstream)

```rust
// None if the path doesn't exist. For single-path mosh use PathId::ZERO.
pub fn rtt(&self, path_id: PathId) -> Option<Duration>;

// Aggregate stats summed across all current AND previously-existing paths.
pub fn stats(&self) -> ConnectionStats;

// Per-path stats. None if path_id unknown. THIS is where rtt/cwnd/current_mtu live.
pub fn path_stats(&self, path_id: PathId) -> Option<PathStats>;

pub fn congestion_state(&self, path_id: PathId) -> Option<Box<dyn Controller>>;
```

### noq_proto::ConnectionStats (re-exported as `iroh::endpoint::ConnectionStats`)
`noq-proto-1.0.0/src/connection/stats.rs:256` — **NO `path` field, NO rtt/cwnd/mtu.**
```rust
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct ConnectionStats {
    pub udp_tx: UdpStats,
    pub udp_rx: UdpStats,
    pub frame_tx: FrameStats,
    pub frame_rx: FrameStats,
    pub lost_packets: u64,   // summed over all paths
    pub lost_bytes: u64,     // summed over all paths
}
```

### noq_proto::PathStats (re-exported as `iroh::endpoint::PathStats`)
`noq-proto-1.0.0/src/connection/stats.rs:215` — get it via `conn.path_stats(PathId::ZERO)`.
```rust
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PathStats {
    pub rtt: Duration,                  // <-- RTT lives here (or via conn.rtt(path_id))
    pub udp_tx: UdpStats,
    pub udp_rx: UdpStats,
    pub frame_tx: FrameStats,
    pub frame_rx: FrameStats,
    pub cwnd: u64,                      // <-- congestion window lives here
    pub congestion_events: u64,
    pub spurious_congestion_events: u64,
    pub lost_packets: u64,
    pub lost_bytes: u64,
    pub sent_plpmtud_probes: u64,
    pub lost_plpmtud_probes: u64,
    pub black_holes_detected: u64,
    pub current_mtu: u16,              // <-- path MTU lives here
}
```
Note: noq `PathStats` has NO `sent_packets` field (upstream quinn does). Sent-datagram count is
`udp_tx.datagrams`.

### noq_proto::UdpStats
`noq-proto-1.0.0/src/connection/stats.rs:16`
```rust
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, derive_more::Add, derive_more::AddAssign)]
#[non_exhaustive]
pub struct UdpStats {
    pub datagrams: u64, // UDP datagram count
    pub bytes: u64,     // total bytes in UDP datagrams
    pub ios: u64,       // syscall count (< datagrams when GSO/GRO/batched)
}
```

### noq_proto::FrameStats (re-exported)
`noq-proto-1.0.0/src/connection/stats.rs:39` — `#[non_exhaustive]`, all `u64` except
`handshake_done: u8`. Multipath-extended vs upstream; notable fields:
`acks, path_acks, ack_frequency, crypto, connection_close, data_blocked, datagram,
handshake_done(u8), immediate_ack, max_data, max_stream_data, max_streams_bidi, max_streams_uni,
new_connection_id, path_new_connection_id, new_token, path_challenge, path_response, ping,
reset_stream, retire_connection_id, path_retire_connection_id, stream_data_blocked,
streams_blocked_bidi, streams_blocked_uni, stop_sending, stream, observed_addr, path_abandon,
path_status_available, path_status_backup, max_path_id, paths_blocked, path_cids_blocked,
add_address, reach_out, remove_address`.
`.datagram` is the DATAGRAM-frame count (use `frame_rx.datagram` / `frame_tx.datagram`).

### noq_proto::PathId (re-exported as `iroh::endpoint::PathId`)
`noq-proto-1.0.0/src/connection/paths.rs:28`
```rust
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default, Hash)]
pub struct PathId(/* private u32 */);
impl PathId {
    pub const MAX: Self  = Self(u32::MAX);
    pub const ZERO: Self = Self(0);   // the initial/default path -- use this for single-path
    pub fn saturating_add(self, rhs: impl Into<Self>) -> Self;
    pub fn saturating_sub(self, rhs: impl Into<Self>) -> Self;
}
// Default::default() == PathId(0) == PathId::ZERO. Inner u32 is private; no public constructor
// besides ZERO/MAX/Default/arithmetic.
```

## Reliable streams (noq — identical signatures to upstream quinn)

`noq::SendStream` (`send_stream.rs`):
```rust
pub async fn write(&mut self, buf: &[u8]) -> Result<usize, WriteError>;     // cancel-safe
pub async fn write_all(&mut self, buf: &[u8]) -> Result<(), WriteError>;    // NOT cancel-safe
pub fn finish(&mut self) -> Result<(), ClosedStream>;                       // signal no-more-data (sync!)
pub fn reset(&mut self, error_code: VarInt) -> Result<(), ClosedStream>;
pub fn set_priority(&self, priority: i32) -> Result<(), ClosedStream>;
pub fn stopped(&self) -> impl Future<Output = Result<Option<VarInt>, StoppedError>> + Send + Sync + 'static;
pub fn id(&self) -> StreamId;
// also impls tokio::io::AsyncWrite. Drop implicitly finish()es.
```

`noq::RecvStream` (`recv_stream.rs`):
```rust
pub async fn read(&mut self, buf: &mut [u8]) -> Result<Option<usize>, ReadError>;       // cancel-safe; Ok(None)=finished
pub async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), ReadExactError>;       // NOT cancel-safe
pub async fn read_to_end(&mut self, size_limit: usize) -> Result<Vec<u8>, ReadToEndError>; // NOT cancel-safe
pub fn stop(&mut self, error_code: VarInt) -> Result<(), ClosedStream>;
pub fn id(&self) -> StreamId;
// also impls tokio::io::AsyncRead. Drop implicitly stop(0)s unless already read/stopped.
```

`open_uni` / `accept_uni` / `open_bi` / `accept_bi` (on `Connection`, identical to upstream):
```rust
pub fn open_uni(&self)   -> OpenUni<'_>;   // Future<Output = Result<SendStream, ConnectionError>>
pub fn open_bi(&self)    -> OpenBi<'_>;    // Future<Output = Result<(SendStream, RecvStream), ConnectionError>>
pub fn accept_uni(&self) -> AcceptUni<'_>; // Future<Output = Result<RecvStream, ConnectionError>>
pub fn accept_bi(&self)  -> AcceptBi<'_>;  // Future<Output = Result<(SendStream, RecvStream), ConnectionError>>
```

`ReadToEndError` (noq, identical to upstream):
```rust
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ReadToEndError {
    Read(#[from] ReadError),  // "read error: {0}"
    TooLong,                  // "stream too long" -- exceeded size_limit; all read data discarded
}
```
`read_to_end` uses **unordered** reads internally for efficiency.

## Connection close / lifecycle (noq, identical to upstream)
```rust
pub fn close(&self, error_code: VarInt, reason: &[u8]); // immediate; pending ops -> LocallyClosed
pub async fn closed(&self) -> ConnectionError;
pub fn close_reason(&self) -> Option<ConnectionError>;  // None while open
```

---

# QUINN UPSTREAM (quinn 0.11.9 / quinn-proto 0.11.14) — only if using raw quinn

## quinn::Connection datagrams
`quinn-0.11.9/src/connection.rs`
```rust
pub fn send_datagram(&self, data: Bytes) -> Result<(), SendDatagramError>;   // :433
pub fn send_datagram_wait(&self, data: Bytes) -> SendDatagram<'_>;            // :461
pub fn read_datagram(&self) -> ReadDatagram<'_>;                             // :349
//   impl Future for ReadDatagram<'_> { type Output = Result<Bytes, ConnectionError>; }   // :799-800
//   impl Future for SendDatagram<'_> { type Output = Result<(), SendDatagramError>; }      // :834-835
pub fn max_datagram_size(&self) -> Option<usize>;                            // :480
pub fn datagram_send_buffer_space(&self) -> usize;                            // :493
pub fn rtt(&self) -> Duration;                                               // :529  (NO path arg)
pub fn stats(&self) -> ConnectionStats;                                       // :534
pub fn congestion_state(&self) -> Box<dyn Controller>;                        // :539
pub fn close(&self, error_code: VarInt, reason: &[u8]);                       // :420
pub async fn closed(&self) -> ConnectionError;                               // :361
pub fn close_reason(&self) -> Option<ConnectionError>;                        // :385
```

### quinn::SendDatagramError
`quinn-0.11.9/src/connection.rs:1297`
```rust
#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum SendDatagramError {
    UnsupportedByPeer,                       // "datagrams not supported by peer"
    Disabled,                                // "datagram support disabled"
    TooLarge,                                // "datagram too large"
    ConnectionLost(#[from] ConnectionError), // "connection lost"
}
```

### quinn-proto ConnectionStats (UPSTREAM — has `path`!)
`quinn-proto-0.11.14/src/connection/stats.rs:163`
```rust
#[derive(Debug, Default, Copy, Clone)]
#[non_exhaustive]
pub struct ConnectionStats {
    pub udp_tx: UdpStats,
    pub udp_rx: UdpStats,
    pub frame_tx: FrameStats,
    pub frame_rx: FrameStats,
    pub path: PathStats,   // <-- single embedded path; NOT present in noq
}
```

### quinn-proto PathStats (UPSTREAM)
`quinn-proto-0.11.14/src/connection/stats.rs:136`
```rust
#[derive(Debug, Default, Copy, Clone)]
#[non_exhaustive]
pub struct PathStats {
    pub rtt: Duration,
    pub cwnd: u64,
    pub congestion_events: u64,
    pub lost_packets: u64,
    pub lost_bytes: u64,
    pub sent_packets: u64,            // <-- upstream-only field (absent in noq)
    pub sent_plpmtud_probes: u64,
    pub lost_plpmtud_probes: u64,
    pub black_holes_detected: u64,
    pub current_mtu: u16,
}
```
Upstream `UdpStats` = `{ datagrams, bytes, ios }` (no derive_more Add). Upstream `FrameStats`
lacks the path_* / multipath fields the noq one has.

## quinn streams (upstream)
`SendStream`: `write`, `write_all`, `finish() -> Result<(), ClosedStream>`, `reset`,
`set_priority`, `stopped`, `id`. `RecvStream`: `read`, `read_exact`,
`read_to_end(size_limit: usize) -> Result<Vec<u8>, ReadToEndError>`, `stop`, `id`.
`ReadToEndError { Read(#[from] ReadError), TooLong }` (`recv_stream.rs:473`). Signatures match
the noq ones above 1:1.

---

# TransportConfig datagram knobs

## noq_proto::TransportConfig (configure via `iroh::endpoint::QuicTransportConfigBuilder`)
`noq-proto-1.0.0/src/config/transport.rs` (same shape as upstream; see below).
iroh wraps it: `QuicTransportConfigBuilder(noq::TransportConfig)`. NOTE iroh docs warn that many
transport settings are tuned for QUIC multipath and changing them may degrade behavior.

## quinn-proto::TransportConfig (upstream)
`quinn-proto-0.11.14/src/config/transport.rs`
```rust
// Max incoming application-datagram bytes buffered; None DISABLES incoming datagrams entirely.
// The peer is forbidden to send a single datagram larger than this.
pub fn datagram_receive_buffer_size(&mut self, value: Option<usize>) -> &mut Self;  // :285
// Default: Some(STREAM_RWND) == Some(1_250_000)  (STREAM_RWND = 12_500_000/1000*100)

// Max outgoing application-datagram bytes buffered. When full, oldest are dropped on new send.
pub fn datagram_send_buffer_size(&mut self, value: usize) -> &mut Self;             // :296
// Default: 1024 * 1024 == 1_048_576

// other relevant builders (all return &mut Self):
pub fn max_idle_timeout(&mut self, value: Option<IdleTimeout>) -> &mut Self;        // default Some(30_000ms)
pub fn keep_alive_interval(&mut self, value: Option<Duration>) -> &mut Self;        // default None
pub fn receive_window(&mut self, value: VarInt) -> &mut Self;                        // default VarInt::MAX
pub fn send_window(&mut self, value: u64) -> &mut Self;
pub fn initial_mtu(&mut self, value: u16) -> &mut Self;
pub fn min_mtu(&mut self, value: u16) -> &mut Self;
```

### `max_datagram_frame_size` — NOT a public TransportConfig knob.
There is no `TransportConfig::max_datagram_frame_size` setter. It is an internal/peer transport
parameter (`peer_params.max_datagram_frame_size`) used only to compute `max_size()`:
`quinn-proto-0.11.14/src/connection/datagrams.rs:69`
```rust
pub fn max_size(&self) -> Option<usize> {
    let max_size = self.conn.path.current_mtu() as usize
        - self.conn.predict_1rtt_overhead(None)
        - Datagram::SIZE_BOUND;
    let limit = self.conn.peer_params.max_datagram_frame_size?      // None => UnsupportedByPeer
        .into_inner()
        .saturating_sub(Datagram::SIZE_BOUND as u64);
    Some(limit.min(max_size as u64) as usize)
}
```
Locally enabling datagram reception (advertising a non-zero max_datagram_frame_size to the peer)
is governed entirely by `datagram_receive_buffer_size`: `Some(_)` enables, `None` disables.
Proto-level `Datagrams::send` returns `Disabled` iff `datagram_receive_buffer_size.is_none()`
(`datagrams.rs:29`). The noq config has the same two fields with identical defaults.

---

# Minimal happy-path: send a Bytes datagram and read one (iroh)

```rust
use bytes::Bytes;
use iroh::endpoint::{Connection, SendDatagramError, PathId};
use std::time::Duration;

async fn datagram_roundtrip(conn: &Connection) -> anyhow::Result<()> {
    // Check capacity (None => peer doesn't support datagrams or locally disabled).
    let max = conn.max_datagram_size().ok_or_else(|| anyhow::anyhow!("datagrams unsupported"))?;

    let payload = Bytes::from_static(b"hello mosh");
    assert!(payload.len() <= max);

    // Non-blocking send (may evict older queued datagrams).
    match conn.send_datagram(payload) {
        Ok(()) => {}
        Err(SendDatagramError::TooLarge) => { /* shrink and retry */ }
        Err(SendDatagramError::UnsupportedByPeer | SendDatagramError::Disabled) => return Ok(()),
        Err(SendDatagramError::ConnectionLost(e)) => return Err(e.into()),
    }
    // Or, to apply backpressure instead of dropping:
    // conn.send_datagram_wait(Bytes::from_static(b"...")).await?;

    // Receive one datagram (ReadDatagram future).
    let dgram: Bytes = conn.read_datagram().await?; // Err(ConnectionError) on close

    // Stats: aggregate has no rtt; rtt/cwnd/mtu are per-path (single-path => PathId::ZERO).
    let rtt: Option<Duration> = conn.rtt(PathId::ZERO);
    let stats = conn.stats();                       // ConnectionStats: udp_tx/udp_rx/frame_tx/frame_rx/lost_*
    let path = conn.path_stats(PathId::ZERO);       // Option<PathStats>: .rtt .cwnd .current_mtu ...
    let _ = (dgram, rtt, stats, path);
    Ok(())
}
```

# Minimal happy-path: one-shot reliable uni stream (iroh, same API as quinn)

```rust
use iroh::endpoint::Connection;

async fn send_blob(conn: &Connection, data: &[u8]) -> anyhow::Result<()> {
    let mut send = conn.open_uni().await?;   // Result<SendStream, ConnectionError>
    send.write_all(data).await?;             // Result<(), WriteError>
    send.finish()?;                          // Result<(), ClosedStream>  (sync; drop also finishes)
    // optionally: send.stopped().await?;    // wait for peer to ack receipt
    Ok(())
}

async fn recv_blob(conn: &Connection, limit: usize) -> anyhow::Result<Vec<u8>> {
    let mut recv = conn.accept_uni().await?;        // Result<RecvStream, ConnectionError>
    let buf = recv.read_to_end(limit).await?;       // Result<Vec<u8>, ReadToEndError>  (TooLong if > limit)
    Ok(buf)
}
```

---

# Gotchas / version-specific notes

- `finish()` is **synchronous** (returns `Result<(), ClosedStream>`), not async, in both quinn and
  noq. It only signals "no more writes"; data keeps retransmitting until acked or connection drops.
  To know the peer received everything, await `SendStream::stopped()`.
- Dropping a `SendStream` implicitly `finish()`es it (continues retransmit). Dropping a
  `RecvStream` implicitly `stop(0)`s it (unless all data read or an error/stop already occurred).
- `read_to_end` discards ALL data and returns `ReadToEndError::TooLong` if the limit is exceeded —
  it does not return partial data. It reads unordered internally.
- `send_datagram` drops oldest unsent queued datagrams to fit the new one (LIFO-prioritizes new).
  Use `send_datagram_wait` for the opposite (backpressure, prioritize old). For mosh's
  send-newest-state semantics, `send_datagram` is the right one.
- `max_datagram_size()` can change over the connection lifetime (path MTU). Re-check it; don't cache.
  Guaranteed `>= ~1KB` only if the peer's advertised limit is large.
- iroh/noq `ConnectionStats` has **no embedded path / rtt / cwnd / mtu**. Do not write
  `conn.stats().path.rtt` (compiles on raw quinn, fails on iroh). Use `conn.rtt(PathId::ZERO)` or
  `conn.path_stats(PathId::ZERO)`.
- iroh/noq `PathStats` has **no `sent_packets`** field; upstream quinn `PathStats` does. For
  sent-datagram counts on noq use `path_stats(..).udp_tx.datagrams` (or `stats().udp_tx.datagrams`
  aggregate).
- iroh `Connection` is generic `Connection<State: ConnectionState = HandshakeCompleted>`; the
  datagram/stream/stats methods live in `impl<T: ConnectionState> Connection<T>`, so they work for
  any state, but you normally hold the defaulted `Connection`.
- `PathId`'s inner `u32` is private; only `PathId::ZERO`, `PathId::MAX`, `Default`, and
  saturating arithmetic are public. Use `PathId::ZERO` for the single/initial path.
- Default datagram buffers (both stacks): receive = `Some(1_250_000)` bytes (enabled), send =
  `1_048_576` bytes. Set `datagram_receive_buffer_size(None)` to disable incoming datagrams (also
  makes local `send_datagram` return `Disabled`).
- There is no public `max_datagram_frame_size` config setter; reception is toggled solely via
  `datagram_receive_buffer_size`.
- noq `FrameStats`/`UdpStats` derive `derive_more::Add`/`AddAssign` (multipath summing); upstream
  quinn versions do not. All stats structs are `#[non_exhaustive]` in both stacks — construct via
  `Default` and read fields; do not pattern-match exhaustively or struct-literal them.
