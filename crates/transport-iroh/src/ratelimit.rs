//! Per-peer failure rate limiter for the passphrase second factor.
//!
//! The Argon2id work factor in [`crate::auth`] makes each online passphrase guess cost the
//! **server** real CPU/memory, so an attacker holding a leaked-but-still-allowlisted client key
//! could both (a) grind passphrases and (b) burn the server's resources doing so. This limiter
//! caps how fast a single peer may fail the handshake: after `max_failures` failures inside a
//! sliding `window_ms`, further attempts are refused **cheaply, before the KDF runs**, until the
//! older failures age out of the window.
//!
//! It is a pure, clock-injected state machine (the caller passes `now` in milliseconds), so it is
//! deterministically testable with no iroh/tokio/clock dependency — matching the `ssp` style.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;

/// Tracks recent authentication failures per key (`K` = the peer's `EndpointId` in the server)
/// over a sliding time window, refusing a key that has failed too many times too recently.
pub struct FailureLimiter<K: Eq + Hash + Clone> {
    /// Length of the trailing window (ms) over which failures are counted.
    window_ms: u64,
    /// Failures within the window at or above which a key is refused.
    max_failures: usize,
    /// Per-key timestamps (ms) of recent failures, oldest at the front.
    fails: HashMap<K, VecDeque<u64>>,
}

impl<K: Eq + Hash + Clone> FailureLimiter<K> {
    /// A limiter that refuses a key once it accumulates `max_failures` failures within the
    /// trailing `window_ms`.
    pub fn new(window_ms: u64, max_failures: usize) -> Self {
        Self {
            window_ms,
            max_failures,
            fails: HashMap::new(),
        }
    }

    /// Whether `key` may attempt right now: `true` unless it has `>= max_failures` failures still
    /// inside the trailing window. Prunes that key's expired failures (and forgets the key
    /// entirely once it has none) as a side effect, so a peer that backs off is cleared.
    pub fn check(&mut self, key: &K, now: u64) -> bool {
        let Some(q) = self.fails.get_mut(key) else {
            return true;
        };
        prune(q, now, self.window_ms);
        let count = q.len();
        if count == 0 {
            self.fails.remove(key);
            return true;
        }
        count < self.max_failures
    }

    /// Record a failed attempt for `key` at `now` (a rejected or timed-out handshake).
    pub fn record_failure(&mut self, key: K, now: u64) {
        let q = self.fails.entry(key).or_default();
        prune(q, now, self.window_ms);
        q.push_back(now);
    }

    /// Forget `key`'s failure history — call on a **successful** handshake so a legitimate client
    /// that mistyped once isn't penalized after it gets in.
    pub fn record_success(&mut self, key: &K) {
        self.fails.remove(key);
    }

    /// Evict every key whose failures have all aged out of the window. Bounds the keyspace under
    /// `--allow-any`, where an unbounded set of distinct peers could each leave a stale entry;
    /// piggyback it on the server's periodic reaper sweep.
    pub fn gc(&mut self, now: u64) {
        let window = self.window_ms;
        self.fails.retain(|_, q| {
            prune(q, now, window);
            !q.is_empty()
        });
    }

    /// Number of keys currently being tracked (for the `--allow-any` keyspace bound / telemetry).
    pub fn tracked_keys(&self) -> usize {
        self.fails.len()
    }
}

/// Drop failures that have aged out of the trailing window from the front of `q`. A failure at
/// time `t` expires once `now >= t + window_ms` (saturating, so a near-`u64::MAX` `t` can't wrap).
fn prune(q: &mut VecDeque<u64>, now: u64, window_ms: u64) {
    while let Some(&front) = q.front() {
        if front.saturating_add(window_ms) <= now {
            q.pop_front();
        } else {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_after_max_failures_within_window_then_recovers() {
        // window 1000ms, 3 failures allowed. Fail at 0/10/20 -> three failures inside the window.
        let mut lim = FailureLimiter::new(1000, 3);
        lim.record_failure("peer", 0);
        lim.record_failure("peer", 10);
        lim.record_failure("peer", 20);
        // At t=30 all three are still inside the 1000ms window -> blocked.
        assert!(
            !lim.check(&"peer", 30),
            "3 failures in the window must block"
        );
        // At t=1001 the t=0 failure has aged out (0 + 1000 <= 1001) -> two remain -> allowed.
        assert!(
            lim.check(&"peer", 1001),
            "an expired failure must free up a slot"
        );
    }

    #[test]
    fn record_success_resets_the_peer() {
        let mut lim = FailureLimiter::new(1000, 3);
        lim.record_failure("peer", 0);
        lim.record_failure("peer", 10);
        lim.record_failure("peer", 20);
        assert!(!lim.check(&"peer", 30), "blocked before success");
        lim.record_success(&"peer");
        assert!(
            lim.check(&"peer", 30),
            "a successful handshake clears the failure history"
        );
        assert_eq!(lim.tracked_keys(), 0, "no residual entry after success");
    }

    #[test]
    fn gc_evicts_keys_whose_failures_all_expired() {
        let mut lim = FailureLimiter::new(1000, 3);
        lim.record_failure("a", 0);
        lim.record_failure("a", 10);
        lim.record_failure("b", 20);
        assert_eq!(lim.tracked_keys(), 2, "two peers tracked");
        // At t=2000 every failure (latest at 20) is older than the 1000ms window.
        lim.gc(2000);
        assert_eq!(lim.tracked_keys(), 0, "gc must evict fully-expired keys");
        // A fresh peer is unaffected and still allowed.
        assert!(lim.check(&"c", 2000));
    }

    #[test]
    fn unknown_key_is_always_allowed() {
        let mut lim = FailureLimiter::new(1000, 3);
        assert!(lim.check(&"never-seen", 0));
        assert_eq!(
            lim.tracked_keys(),
            0,
            "checking an unknown key must not allocate an entry"
        );
    }
}
