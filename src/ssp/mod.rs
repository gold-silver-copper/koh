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
pub use transport::{RecvOutcome, Transport};

/// `u64::MAX` doubles as both the "never" deadline and the shutdown state sentinel,
/// exactly as mosh uses `uint64_t(-1)`.
pub const NEVER: u64 = u64::MAX;
/// The state number that signals a clean shutdown (`uint64_t(-1)` in mosh).
pub const SHUTDOWN_SENTINEL: u64 = u64::MAX;

// --- scheduler constants (mosh `transportsender.h`, milliseconds) ---
// `pub(crate)`: internal SSP tuning knobs, referenced only within `src/ssp`; not public API.
/// Floor on the inter-frame interval.
pub(crate) const SEND_INTERVAL_MIN: u64 = 20;
/// Ceiling on the inter-frame interval.
pub(crate) const SEND_INTERVAL_MAX: u64 = 250;
/// Interval between empty keep-alive acks when otherwise idle.
pub(crate) const ACK_INTERVAL: u64 = 3000;
/// Delay before a coalesced data-ack is flushed.
pub(crate) const ACK_DELAY: u64 = 100;
/// Minimum coalescing window for a burst of new input before sending.
pub(crate) const SEND_MINDELAY: u64 = 8;
/// Stop retransmitting if the peer has been silent this long (it may be roaming).
pub(crate) const ACTIVE_RETRY_TIMEOUT: u64 = 10_000;
/// Shutdown sentinel resends before giving up.
pub(crate) const SHUTDOWN_RETRIES: u32 = 16;
/// `sent_states` queue cap; the 16th-from-end is dropped when exceeded.
pub(crate) const SENT_STATES_CAP: usize = 32;
/// Hard ceiling on the number of retained `received_states` (anti-accumulation).
///
/// Inbound states beyond this are refused outright (not merely rate-limited), so a hostile peer
/// that pins `old_num`/`throwaway_num` to prevent collapse cannot grow the list without bound
/// (KOH-01). The per-state-type [`SyncState::RECEIVE_BUDGET_UNITS`] is the companion byte bound.
pub(crate) const RECEIVED_STATES_CAP: usize = 1024;

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

    /// Per-direction cap (bytes) on how large an inbound instruction targeting *this* state may
    /// inflate to, an anti-amplification bound on untrusted peer input (KOH-02). Keystroke input
    /// (`UserInput`) needs only a few hundred KiB even for a big paste; a screen repaint
    /// (`TerminalScreen`) needs more.
    ///
    /// **Required (no default).** Previously this defaulted to the 16 MiB global ceiling, which meant
    /// a new received-state type that forgot to set it silently inherited a generous cap; making it
    /// required forces every state type to declare its bound consciously (AR-05). A cost-free/trusted
    /// stub may set it to [`crate::wire::MAX_DECOMPRESSED`] explicitly.
    const RECV_DECODE_LIMIT: usize;

    /// Total resource budget (in [`resource_units`](SyncState::resource_units)) summed across every
    /// *received* copy of this state the transport will retain before it refuses further inbound
    /// states as a resource-exhaustion attack (KOH-01). A hostile-but-authorized peer can pin
    /// `old_num`/`throwaway_num` so the receiver never collapses its `received_states`; this bounds
    /// the memory that accumulation can pin.
    ///
    /// **Required (no default).** This previously defaulted to [`usize::MAX`] (*unbounded*) — the
    /// unsafe value — so a new received-state type that forgot it silently opted OUT of the KOH-01
    /// accumulation bound. Required so the choice is conscious (AR-05); a cost-free stub may set
    /// `usize::MAX` explicitly.
    const RECEIVE_BUDGET_UNITS: usize;

    /// This state's current resource cost, in the same units as
    /// [`RECEIVE_BUDGET_UNITS`](SyncState::RECEIVE_BUDGET_UNITS). Called once per inbound state, so
    /// it must be cheap (an `O(1)`/length read, never a deep walk).
    ///
    /// **Required (no default).** Previously defaulted to `0`, which combined with the budget to
    /// silently disable the byte/units bound (everything "costs nothing"); required so each type
    /// states its cost model (AR-05).
    fn resource_units(&self) -> usize;

    /// Produce a diff that, applied to `base`, yields `self` (delta `base → self`).
    fn diff_from(&self, base: &Self) -> Self::Diff;

    /// Apply a diff in place (`self` was the diff's base; becomes the diff's target).
    fn apply(&mut self, diff: &Self::Diff);

    /// Collapse storage by dropping the `prefix` already known to the peer.
    ///
    /// Default is a no-op (correct but unbounded). [`crate::input::UserInput`] overrides
    /// this to pop acked keystrokes; the screen state leaves it as the no-op.
    fn subtract_prefix(&mut self, _prefix: &Self) {}
}
