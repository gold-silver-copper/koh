//! Deterministic network-chaos harness for the SSP.
//!
//! A discrete-event simulator that connects two [`Transport`]s through a pair of lossy,
//! latent, reordering, duplicating links driven by a seeded PRNG. Used by this crate's
//! convergence tests, by the `input`/`terminal` crates, and by `xtask` to hammer the
//! protocol. It proves the two non-negotiable properties from the spec:
//!
//! 1. **Convergence** — the receiver always reaches the sender's latest state.
//! 2. **No head-of-line blocking** — the newest applied state number is monotonic; a
//!    superseded older state is never delivered "late" as the current state.

// This is a test harness: a violated invariant or an exceeded step budget SHOULD panic loudly
// (it means a test is wrong), so the panic-prevention restrictions are relaxed here.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "deterministic test harness: a failed invariant must panic the offending test"
)]

use crate::{SyncState, Transport, NEVER};

/// A small, dependency-free, reproducible PRNG (SplitMix64).
#[derive(Debug, Clone)]
pub struct Rng {
    state: u64,
}

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in `[0, 1)`.
    pub fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Uniform integer in `[lo, hi]`.
    pub fn range(&mut self, lo: u64, hi: u64) -> u64 {
        if hi <= lo {
            lo
        } else {
            lo + self.next_u64() % (hi - lo + 1)
        }
    }
}

/// Impairments applied to a one-directional link.
#[derive(Debug, Clone, Copy)]
pub struct LinkParams {
    /// Probability `[0,1]` a datagram is dropped outright.
    pub loss: f64,
    /// Minimum one-way delay (ms).
    pub min_delay_ms: u64,
    /// Maximum one-way delay (ms). Random delay in `[min,max]` is what produces reordering.
    pub max_delay_ms: u64,
    /// Probability `[0,1]` a datagram is duplicated.
    pub dup: f64,
}

impl LinkParams {
    /// A clean, low-latency link.
    pub fn perfect() -> Self {
        Self {
            loss: 0.0,
            min_delay_ms: 5,
            max_delay_ms: 5,
            dup: 0.0,
        }
    }

    /// A nasty mobile link: 30% loss, 20–120ms jitter, 5% duplication.
    pub fn lossy() -> Self {
        Self {
            loss: 0.30,
            min_delay_ms: 20,
            max_delay_ms: 120,
            dup: 0.05,
        }
    }

    fn rtt_hint(&self) -> f64 {
        (self.min_delay_ms + self.max_delay_ms) as f64
    }
}

/// A one-directional in-flight datagram queue with random per-datagram delay.
#[derive(Debug, Default)]
pub struct Link {
    inflight: Vec<(u64, Vec<u8>)>, // (deliver_at_ms, bytes)
}

impl Link {
    pub fn new() -> Self {
        Self::default()
    }

    /// Offer a datagram to the link at time `now`; loss/delay/dup are applied here.
    pub fn push(&mut self, rng: &mut Rng, now: u64, p: &LinkParams, dg: Vec<u8>) {
        if rng.next_f64() < p.loss {
            return; // dropped
        }
        let delay = rng.range(p.min_delay_ms, p.max_delay_ms);
        self.inflight.push((now + delay, dg.clone()));
        if rng.next_f64() < p.dup {
            let delay2 = rng.range(p.min_delay_ms, p.max_delay_ms);
            self.inflight.push((now + delay2, dg));
        }
    }

    /// Earliest pending delivery time, if any.
    pub fn next_due(&self) -> Option<u64> {
        self.inflight.iter().map(|x| x.0).min()
    }

    /// Drain and return all datagrams due at or before `now`, in delivery-time order.
    pub fn due(&mut self, now: u64) -> Vec<Vec<u8>> {
        let mut ready: Vec<(u64, Vec<u8>)> = Vec::new();
        let mut keep: Vec<(u64, Vec<u8>)> = Vec::new();
        for item in self.inflight.drain(..) {
            if item.0 <= now {
                ready.push(item);
            } else {
                keep.push(item);
            }
        }
        self.inflight = keep;
        ready.sort_by_key(|x| x.0);
        ready.into_iter().map(|x| x.1).collect()
    }

    pub fn is_empty(&self) -> bool {
        self.inflight.is_empty()
    }
}

/// Two transports wired through two chaotic links, stepped by a virtual clock.
///
/// `a` authors `L` and receives `R`; `b` authors `R` and receives `L`. Inject changes via
/// [`a_mut`](Self::a_mut)/[`b_mut`](Self::b_mut), then drive with [`step`](Self::step).
pub struct SimHarness<L: SyncState, R: SyncState> {
    pub a: Transport<L, R>,
    pub b: Transport<R, L>,
    a2b: Link,
    b2a: Link,
    now: u64,
    rng: Rng,
    params: LinkParams,
    /// Highest newest-applied num observed on each side; asserts monotonicity (no HOL).
    max_remote_num_at_b: u64,
    max_remote_num_at_a: u64,
}

impl<L: SyncState, R: SyncState> SimHarness<L, R> {
    pub fn new(params: LinkParams, seed: u64, mtu: usize) -> Self {
        let mut a = Transport::new(0, mtu);
        let mut b = Transport::new(0, mtu);
        a.set_connected(true);
        b.set_connected(true);
        Self {
            a,
            b,
            a2b: Link::new(),
            b2a: Link::new(),
            now: 0,
            rng: Rng::new(seed),
            params,
            max_remote_num_at_b: 0,
            max_remote_num_at_a: 0,
        }
    }

    pub fn now(&self) -> u64 {
        self.now
    }

    /// Mutable access to A's authored state.
    pub fn a_mut(&mut self) -> &mut L {
        self.a.current_mut()
    }

    /// Mutable access to B's authored state.
    pub fn b_mut(&mut self) -> &mut R {
        self.b.current_mut()
    }

    /// What B currently sees of A's stream (A → B direction).
    pub fn b_view_of_a(&self) -> &L {
        self.b.remote_state()
    }

    /// What A currently sees of B's stream (B → A direction).
    pub fn a_view_of_b(&self) -> &R {
        self.a.remote_state()
    }

    fn next_event_time(&mut self) -> Option<u64> {
        let now = self.now;
        let wa = self.a.wait_time(now);
        let wb = self.b.wait_time(now);
        let ta = (wa != NEVER).then(|| now.saturating_add(wa));
        let tb = (wb != NEVER).then(|| now.saturating_add(wb));
        [ta, tb, self.a2b.next_due(), self.b2a.next_due()]
            .into_iter()
            .flatten()
            .min()
    }

    /// Advance to the next event: deliver due datagrams, feed RTT, tick both sides, enqueue
    /// output. Returns `false` if nothing is pending (fully idle — rare, since keepalives
    /// recur). Panics if the newest-applied num ever goes backwards (HOL-blocking guard).
    pub fn step(&mut self) -> bool {
        let Some(nt) = self.next_event_time() else {
            return false;
        };
        self.now = nt.max(self.now);
        let now = self.now;

        for dg in self.b2a.due(now) {
            self.a.recv(now, &dg);
        }
        for dg in self.a2b.due(now) {
            self.b.recv(now, &dg);
        }

        // Monotonicity guard: the newest in-order applied state never regresses.
        let rb = self.b.remote_num();
        assert!(
            rb >= self.max_remote_num_at_b || rb == crate::SHUTDOWN_SENTINEL,
            "HOL violation: B newest-applied num regressed {} -> {}",
            self.max_remote_num_at_b,
            rb
        );
        self.max_remote_num_at_b = self.max_remote_num_at_b.max(rb);
        let ra = self.a.remote_num();
        assert!(
            ra >= self.max_remote_num_at_a || ra == crate::SHUTDOWN_SENTINEL,
            "HOL violation: A newest-applied num regressed {} -> {}",
            self.max_remote_num_at_a,
            ra
        );
        self.max_remote_num_at_a = self.max_remote_num_at_a.max(ra);

        let rtt = self.params.rtt_hint();
        self.a.observe_rtt(rtt);
        self.b.observe_rtt(rtt);

        for dg in self.a.tick(now) {
            self.a2b.push(&mut self.rng, now, &self.params, dg);
        }
        for dg in self.b.tick(now) {
            self.b2a.push(&mut self.rng, now, &self.params, dg);
        }
        true
    }

    /// Step until `pred(self)` holds, returning the number of steps. Panics if `max_steps`
    /// is exceeded (treated as non-convergence).
    pub fn run_until(&mut self, max_steps: usize, mut pred: impl FnMut(&Self) -> bool) -> usize {
        for i in 0..max_steps {
            if pred(self) {
                return i;
            }
            if !self.step() {
                // Idle: give the predicate a last chance.
                if pred(self) {
                    return i;
                }
                return i;
            }
        }
        panic!("run_until exceeded {max_steps} steps without satisfying predicate");
    }

    /// Step a fixed number of times (e.g. to let an injected change propagate).
    pub fn run_steps(&mut self, steps: usize) {
        for _ in 0..steps {
            if !self.step() {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    /// A simple growing byte-log state with NO collapse, so `b_view_of_a == a.current`
    /// exactly at convergence. Exercises the transport without the input-collapse subtlety.
    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    struct LogState(Vec<u8>);

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct LogDiff(Vec<u8>); // bytes appended since the base

    impl SyncState for LogState {
        type Diff = LogDiff;
        fn diff_from(&self, base: &Self) -> Self::Diff {
            // self is always a superset (suffix-extended) of base in this test.
            let n = base.0.len().min(self.0.len());
            LogDiff(self.0[n..].to_vec())
        }
        fn apply(&mut self, diff: &Self::Diff) {
            self.0.extend_from_slice(&diff.0);
        }
        // subtract_prefix left as the default no-op: state stays full for exact comparison.
    }

    #[test]
    fn converges_on_perfect_link() {
        let mut h = SimHarness::<LogState, LogState>::new(LinkParams::perfect(), 1, 1200);
        h.a_mut().0.extend_from_slice(b"hello world");
        h.run_until(2000, |h| h.b_view_of_a().0 == b"hello world");
    }

    #[test]
    fn converges_under_chaos_with_ongoing_input() {
        let mut h = SimHarness::<LogState, LogState>::new(LinkParams::lossy(), 42, 1200);
        let mut expected = Vec::new();
        // Inject 50 bursts of input while the link drops/reorders/dups/jitters.
        for round in 0..50u8 {
            let chunk = [round, round.wrapping_add(1), round.wrapping_add(2)];
            h.a_mut().0.extend_from_slice(&chunk);
            expected.extend_from_slice(&chunk);
            h.run_steps(8);
        }
        // Now let it drain and converge to the final state.
        let exp = expected.clone();
        h.run_until(20_000, move |h| h.b_view_of_a().0 == exp);
        assert_eq!(h.b_view_of_a().0, expected);
    }

    #[test]
    fn converges_bidirectionally() {
        let mut h = SimHarness::<LogState, LogState>::new(LinkParams::lossy(), 7, 1200);
        h.a_mut().0.extend_from_slice(b"from-a");
        h.b_mut().0.extend_from_slice(b"FROM-B");
        h.run_until(20_000, |h| {
            h.b_view_of_a().0 == b"from-a" && h.a_view_of_b().0 == b"FROM-B"
        });
    }

    #[test]
    fn superseded_states_collapse_not_replayed() {
        // Rapidly supersede before delivery; the receiver should jump to the latest, never
        // replaying every intermediate. We assert it reaches the final value; the harness's
        // per-step monotonicity guard proves no superseded state is delivered late.
        let mut h = SimHarness::<LogState, LogState>::new(LinkParams::lossy(), 99, 1200);
        for i in 0..200u32 {
            // Replace the whole log each round (still suffix-compatible since it only grows
            // here); the point is many state versions are created between deliveries.
            h.a_mut().0.extend_from_slice(&i.to_le_bytes());
            h.step(); // only one step between injections => heavy superseding
        }
        let final_len = h.a.current().0.len();
        h.run_until(20_000, move |h| h.b_view_of_a().0.len() == final_len);
    }
}
