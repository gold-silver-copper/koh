//! # koh-ssp — State Synchronization Protocol
//!
//! A faithful Rust port of mosh's SSP, retargeted onto QUIC unreliable datagrams.
//!
//! The protocol's only job is to bring the peer to the *latest* version of an
//! authoritative object. Intermediate states are collapsed and discarded — if the
//! object changed 100 times in 40ms, only the final state is transmitted. This is the
//! source of mosh's instant recovery, lossy-link responsiveness, and absence of
//! head-of-line blocking.
//!
//! ## What this crate is (and isn't)
//!
//! [`Transport`] is a **pure state machine**. It owns no sockets, no clock, no async.
//! The caller (the iroh driver, or a test harness) supplies the current time in
//! milliseconds and the path RTT, calls [`Transport::tick`] to get datagrams to send,
//! and feeds inbound datagrams to [`Transport::recv`]. This makes the whole protocol
//! deterministically testable under simulated loss/latency/reordering — see [`testkit`].
//!
//! ## The transport-layer division of labor (vs. mosh)
//!
//! QUIC/iroh subsumes mosh's UDP framing, OCB crypto, key exchange, roaming, NAT
//! traversal, heartbeats, and RTT measurement. This crate keeps only what lives *above*
//! the wire: the `sent_states`/`received_states` collapse logic, the `tick()` send
//! scheduler, the seq/ack/throwaway envelope, and fragmentation (in [`koh_wire`]).

use serde::de::DeserializeOwned;
use serde::Serialize;

mod rtt;
pub mod testkit;
mod transport;

pub use rtt::RttEstimator;
pub use transport::{RecvOutcome, TimestampedState, Transport};

/// `u64::MAX` doubles as both the "never" deadline and the shutdown state sentinel,
/// exactly as mosh uses `uint64_t(-1)`.
pub const NEVER: u64 = u64::MAX;
/// The state number that signals a clean shutdown (`uint64_t(-1)` in mosh).
pub const SHUTDOWN_SENTINEL: u64 = u64::MAX;

// --- scheduler constants (mosh `transportsender.h`, milliseconds) ---
/// Floor on the inter-frame interval.
pub const SEND_INTERVAL_MIN: u64 = 20;
/// Ceiling on the inter-frame interval.
pub const SEND_INTERVAL_MAX: u64 = 250;
/// Interval between empty keep-alive acks when otherwise idle.
pub const ACK_INTERVAL: u64 = 3000;
/// Delay before a coalesced data-ack is flushed.
pub const ACK_DELAY: u64 = 100;
/// Minimum coalescing window for a burst of new input before sending.
pub const SEND_MINDELAY: u64 = 8;
/// Stop retransmitting if the peer has been silent this long (it may be roaming).
pub const ACTIVE_RETRY_TIMEOUT: u64 = 10_000;
/// Shutdown sentinel resends before giving up.
pub const SHUTDOWN_RETRIES: u32 = 16;
/// `sent_states` queue cap; the 16th-from-end is dropped when exceeded.
pub const SENT_STATES_CAP: usize = 32;
/// `received_states` anti-DoS cap; beyond this a 15s quench window applies.
pub const RECEIVED_STATES_CAP: usize = 1024;
/// Quench window once `received_states` exceeds [`RECEIVED_STATES_CAP`].
pub const RECEIVER_QUENCH_MS: u64 = 15_000;

/// A synchronizable object: the unit the protocol keeps in sync.
///
/// Implementors are the screen ([`koh_terminal`]) and the user-input stream
/// ([`koh_input`]). The contract mirrors mosh's `MyState`/`RemoteState`:
///
/// - [`diff_from`](SyncState::diff_from): produce the delta that transforms `base` into `self`.
/// - [`apply`](SyncState::apply): mutate `self` by applying a delta.
/// - [`subtract_prefix`](SyncState::subtract_prefix): physically drop an already-acked
///   prefix from storage (an optimization; the default no-op is always *correct* because
///   diffs are computed from explicit base states).
///
/// ## The round-trip law every implementor must satisfy
///
/// The delta goes *base → self*, so for any `base, target`:
/// `let mut c = base.clone(); c.apply(&target.diff_from(&base)); assert_eq!(c, target);`
pub trait SyncState: Clone + Default + PartialEq {
    /// The serializable delta type.
    type Diff: Serialize + DeserializeOwned;

    /// Produce a diff that, applied to `base`, yields `self` (delta `base → self`).
    fn diff_from(&self, base: &Self) -> Self::Diff;

    /// Apply a diff in place (`self` was the diff's base; becomes the diff's target).
    fn apply(&mut self, diff: &Self::Diff);

    /// Collapse storage by dropping the `prefix` already known to the peer.
    ///
    /// Default is a no-op (correct but unbounded). [`koh_input::UserInput`] overrides
    /// this to pop acked keystrokes; the screen state leaves it as the no-op.
    fn subtract_prefix(&mut self, _prefix: &Self) {}
}
