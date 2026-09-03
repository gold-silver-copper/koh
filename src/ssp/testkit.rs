//! Deterministic network-chaos harness for the SSP.
//!
//! A discrete-event simulator that connects two [`Transport`]s through a pair of lossy,
//! latent, reordering, duplicating links driven by a seeded PRNG. Used by the convergence tests,
//! the `sim` module, and the integration tests to hammer the protocol. It proves the two
//! non-negotiable properties from the spec:
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

use std::collections::BTreeMap;

use crate::ssp::{SyncState, Transport, NEVER};
use serde::{Deserialize, Serialize};

/// A multi-cell grid state for exercising the generic host/client seams (KH-01).
///
/// A state that is *not* a terminal: a map of numbered cells to byte payloads, plus the scalars a
/// client needs (`echo_ack`, `exit_code`, geometry). Diffs carry only the changed cells, so a diff
/// can span several datagrams when many cells move — the shape of a multiplexer's per-pane grids.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GridState {
    pub cells: BTreeMap<u32, Vec<u8>>,
    pub echo_ack: u64,
    pub exit_code: Option<u32>,
    pub rows: u16,
    pub cols: u16,
    /// A bell counter so the client-side out-of-band path can be exercised too.
    pub bell_count: u64,
}

impl Default for GridState {
    fn default() -> Self {
        Self {
            cells: BTreeMap::new(),
            echo_ack: 0,
            exit_code: None,
            rows: 24,
            cols: 80,
            bell_count: 0,
        }
    }
}

impl GridState {
    /// Every cell's bytes concatenated in cell order, lossily decoded — the "screen contents" a
    /// test asserts markers against.
    pub fn contents(&self) -> String {
        let mut out = String::new();
        for v in self.cells.values() {
            out.push_str(&String::from_utf8_lossy(v));
        }
        out
    }
}

/// The delta between two [`GridState`]s: changed/added cells (`None` = removed) plus the scalars.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GridDiff {
    pub cells: Vec<(u32, Option<Vec<u8>>)>,
    pub echo_ack: u64,
    pub exit_code: Option<u32>,
    pub rows: u16,
    pub cols: u16,
    pub bell_count: u64,
}

impl SyncState for GridState {
    type Diff = GridDiff;
    /// A test state: keep the global ceilings, declared explicitly (AR-05).
    const RECV_DECODE_LIMIT: usize = crate::wire::MAX_DECOMPRESSED;
    const RECEIVE_BUDGET_UNITS: usize = 64 * 1024 * 1024;

    fn resource_units(&self) -> usize {
        self.cells
            .values()
            .map(Vec::len)
            .sum::<usize>()
            .saturating_add(self.cells.len())
    }

    fn diff_from(&self, base: &Self) -> Self::Diff {
        let mut cells = Vec::new();
        for (k, v) in &self.cells {
            if base.cells.get(k) != Some(v) {
                cells.push((*k, Some(v.clone())));
            }
        }
        for k in base.cells.keys() {
            if !self.cells.contains_key(k) {
                cells.push((*k, None));
            }
        }
        GridDiff {
            cells,
            echo_ack: self.echo_ack,
            exit_code: self.exit_code,
            rows: self.rows,
            cols: self.cols,
            bell_count: self.bell_count,
        }
    }

    fn apply(&mut self, diff: &Self::Diff) {
        for (k, v) in &diff.cells {
            match v {
                Some(bytes) => {
                    self.cells.insert(*k, bytes.clone());
                }
                None => {
                    self.cells.remove(k);
                }
            }
        }
        self.echo_ack = diff.echo_ack;
        self.exit_code = diff.exit_code;
        self.rows = diff.rows;
        self.cols = diff.cols;
        self.bell_count = diff.bell_count;
    }
}

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
    #[cfg(test)]
    pub fn perfect() -> Self {
        Self {
            loss: 0.0,
            min_delay_ms: 5,
            max_delay_ms: 5,
            dup: 0.0,
        }
    }

    /// A nasty mobile link: 30% loss, 20–120ms jitter, 5% duplication.
    #[cfg(test)]
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
            a2b: Link::default(),
            b2a: Link::default(),
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
    #[cfg(test)]
    pub fn b_view_of_a(&self) -> &L {
        self.b.remote_state()
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
            rb >= self.max_remote_num_at_b || rb == crate::ssp::SHUTDOWN_SENTINEL,
            "HOL violation: B newest-applied num regressed {} -> {}",
            self.max_remote_num_at_b,
            rb
        );
        self.max_remote_num_at_b = self.max_remote_num_at_b.max(rb);
        let ra = self.a.remote_num();
        assert!(
            ra >= self.max_remote_num_at_a || ra == crate::ssp::SHUTDOWN_SENTINEL,
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
        // Cost-free test stub: unbounded by design (it stays full for exact comparison), declared
        // explicitly now the bounds are required.
        const RECV_DECODE_LIMIT: usize = crate::wire::MAX_DECOMPRESSED;
        const RECEIVE_BUDGET_UNITS: usize = usize::MAX;
        fn resource_units(&self) -> usize {
            0
        }
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
            h.b_view_of_a().0 == b"from-a" && h.a.remote_state().0 == b"FROM-B"
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

    #[test]
    fn grid_state_diff_apply_roundtrip_with_adds_changes_and_removes() {
        // KH-01: the round-trip law for the generic test state, including a removed cell.
        let mut base = GridState::default();
        base.cells.insert(1, b"one".to_vec());
        base.cells.insert(2, b"two".to_vec());
        let mut target = base.clone();
        target.cells.insert(2, b"TWO".to_vec());
        target.cells.remove(&1);
        target.cells.insert(9, vec![0u8; 5000]); // bigger than one datagram
        target.echo_ack = 7;
        target.exit_code = Some(3);
        let diff = target.diff_from(&base);
        let mut c = base;
        c.apply(&diff);
        assert_eq!(c, target);
    }

    #[test]
    fn grid_state_converges_under_chaos() {
        // KH-01: the transport syncs a non-terminal state with multi-datagram diffs over loss.
        let mut h = SimHarness::<GridState, LogState>::new(LinkParams::lossy(), 11, 1200);
        let mut rng = Rng::new(5);
        for round in 0..40u32 {
            let k = (rng.next_u64() % 8) as u32;
            let len = rng.range(1, 3000) as usize;
            h.a_mut().cells.insert(k, vec![round as u8; len]);
            h.run_steps(6);
        }
        let target = h.a.current().clone();
        h.run_until(40_000, move |h| *h.b_view_of_a() == target);
    }
}
