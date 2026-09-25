//! RTT/RTO estimation.
//!
//! Under iroh, quinn already measures a smoothed path RTT (`Connection::rtt()`). We feed
//! those samples into mosh's own Jacobson/Karels estimator so the send scheduler keeps
//! mosh's exact `send_interval()` ("two frames per RTT") and `timeout()` (RTO) behavior.
//! Using these instead of raw quinn RTT keeps the timer math identical to upstream mosh.

// Deliberately NOT using `f64::mul_add` here: a fused multiply-add rounds differently from the
// separate `*` and `+`, which would diverge from mosh's exact EWMA/RTO arithmetic (the whole point
// of this module is byte-for-byte timer parity with upstream).
#![expect(
    clippy::suboptimal_flops,
    reason = "preserve mosh's exact non-FMA timer arithmetic"
)]

use tracing::trace;

use crate::ssp::{SEND_INTERVAL_MAX, SEND_INTERVAL_MIN};

/// Smoothed RTT / RTO estimator (mosh `Network::Connection` initial values + update rule).
#[derive(Debug)]
pub struct RttEstimator {
    srtt: f64,
    rttvar: f64,
    hit: bool,
    /// The last sample actually incorporated. The driver calls `observe_rtt` every wakeup, but
    /// quinn only refreshes its smoothed RTT on an ACK — so the *same* value arrives repeatedly
    /// between ACKs. Dropping an unchanged repeat keeps those repeats from dragging the EWMA
    /// (notably decaying `rttvar`, which would tighten the RTO toward `srtt`).
    last: Option<f64>,
}

impl Default for RttEstimator {
    fn default() -> Self {
        // mosh init: SRTT = 1000, RTTVAR = 500, RTT_hit = false.
        Self {
            srtt: 1000.0,
            rttvar: 500.0,
            hit: false,
            last: None,
        }
    }
}

impl RttEstimator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Incorporate an RTT sample (milliseconds). Samples ≥ 5000ms are ignored as outliers,
    /// matching mosh.
    pub fn sample(&mut self, r_ms: f64) {
        if !(r_ms.is_finite()) || r_ms >= 5000.0 {
            return;
        }
        // Skip an unchanged repeat (quinn only updates its RTT on an ACK; we sample every wakeup).
        if self.last == Some(r_ms) {
            return;
        }
        self.last = Some(r_ms);
        if self.hit {
            self.rttvar = 0.75 * self.rttvar + 0.25 * (self.srtt - r_ms).abs();
            self.srtt = 0.875 * self.srtt + 0.125 * r_ms;
        } else {
            self.srtt = r_ms;
            self.rttvar = r_ms / 2.0;
            self.hit = true;
        }
        trace!(
            sample = r_ms,
            srtt = self.srtt,
            rttvar = self.rttvar,
            "rtt sample"
        );
    }

    /// Smoothed RTT in milliseconds. Test-only: production reads the send interval via
    /// [`send_interval`](Self::send_interval), not the raw SRTT.
    #[cfg(test)]
    pub const fn srtt_ms(&self) -> f64 {
        self.srtt
    }

    /// Retransmission timeout (RTO), `clamp(ceil(SRTT + 4·RTTVAR), 50, 1000)` ms.
    pub fn timeout(&self) -> u64 {
        ceil_clamp(self.srtt + 4.0 * self.rttvar, 50, 1000)
    }

    /// Inter-frame send interval, `clamp(ceil(SRTT / 2), 20, 250)` ms ("two frames per RTT").
    pub fn send_interval(&self) -> u64 {
        ceil_clamp(self.srtt / 2.0, SEND_INTERVAL_MIN, SEND_INTERVAL_MAX)
    }
}

/// `clamp(ceil(x), lo, hi)` for `lo < hi`, computed without a float-to-int `as` cast. It returns
/// exactly what mosh's `(x.ceil() as i64).clamp(lo, hi)` does, including for non-finite `x`: the
/// cast saturates infinities and maps NaN to 0, which the clamp then raises to `lo`.
fn ceil_clamp(x: f64, lo: u32, hi: u32) -> u64 {
    if x.is_nan() || x <= f64::from(lo) {
        return lo.into();
    }
    if x >= f64::from(hi) {
        return hi.into();
    }
    // Now `lo < x < hi`, so `ceil(x)` is the smallest integer in `lo + 1..=hi` that is `>= x`.
    // Bisect for it; every `u32` is exact as an `f64`, so each comparison is exact.
    let (mut below, mut at_or_above) = (lo, hi);
    while below.abs_diff(at_or_above) > 1 {
        let mid = below.midpoint(at_or_above);
        if f64::from(mid) >= x {
            at_or_above = mid;
        } else {
            below = mid;
        }
    }
    at_or_above.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_values_match_mosh() {
        let e = RttEstimator::new();
        // SRTT=1000, RTTVAR=500 => RTO = clamp(1000+2000,50,1000) = 1000; interval clamp(500,20,250)=250.
        assert_eq!(e.timeout(), 1000);
        assert_eq!(e.send_interval(), 250);
    }

    #[test]
    fn send_interval_is_clamped_half_srtt() {
        // This is the quantity the adaptive predictor is tuned against (mosh feeds the same): on a
        // ~100ms link the interval is ~50 (so engage at SRTT>60 vs the predictor's 30ms threshold).
        let mut mid = RttEstimator::new();
        for _ in 0..200 {
            mid.sample(100.0);
        }
        assert!(
            (45..=55).contains(&mid.send_interval()),
            "≈ srtt/2 = 50, got {}",
            mid.send_interval()
        );
        // A fast link clamps to the floor; a slow link to the ceiling.
        let mut fast = RttEstimator::new();
        for _ in 0..200 {
            fast.sample(2.0);
        }
        assert_eq!(fast.send_interval(), u64::from(SEND_INTERVAL_MIN));
        let mut slow = RttEstimator::new();
        for _ in 0..200 {
            slow.sample(1000.0);
        }
        assert_eq!(slow.send_interval(), u64::from(SEND_INTERVAL_MAX));
    }

    #[test]
    fn converges_to_low_rtt() {
        let mut e = RttEstimator::new();
        for _ in 0..200 {
            e.sample(10.0);
        }
        assert!((e.srtt_ms() - 10.0).abs() < 1.0);
        assert_eq!(e.timeout(), 50); // floor
        assert_eq!(e.send_interval(), 20); // floor
    }

    #[test]
    fn ignores_outliers() {
        let mut e = RttEstimator::new();
        e.sample(40.0); // first sample seeds
        let before = e.srtt_ms();
        e.sample(9000.0); // ignored
        // Bit-for-bit: the outlier must not move the estimate at all.
        assert_eq!(e.srtt_ms().to_bits(), before.to_bits());
    }

    #[test]
    fn repeated_identical_samples_do_not_drift_ewma() {
        let mut e = RttEstimator::new();
        e.sample(100.0); // seed
        e.sample(20.0); // a genuine change establishes a non-trivial srtt + rttvar
        let srtt = e.srtt_ms();
        let rto = e.timeout();
        // quinn only updates its RTT on an ACK; between ACKs the SAME value is sampled each wakeup.
        for _ in 0..100 {
            e.sample(20.0);
        }
        // Compared bit-for-bit, not approximately: the EWMA must not drift at all.
        assert_eq!(
            e.srtt_ms().to_bits(),
            srtt.to_bits(),
            "srtt must not drift on a repeated identical sample"
        );
        assert_eq!(
            e.timeout(),
            rto,
            "rttvar (hence the RTO) must not decay on repeats"
        );
        // A genuinely different sample is still incorporated.
        e.sample(21.0);
        assert_ne!(
            e.srtt_ms().to_bits(),
            srtt.to_bits(),
            "a changed sample still updates the estimate"
        );
    }

    /// The old `as`-cast formula, kept as the reference `ceil_clamp` must match bit for bit.
    fn ceil_clamp_by_cast(x: f64, lo: u32, hi: u32) -> u64 {
        (x.ceil() as i64).clamp(i64::from(lo), i64::from(hi)) as u64
    }

    #[test]
    fn ceil_clamp_matches_the_cast_formula_at_the_edges() {
        for (lo, hi) in [(50, 1000), (SEND_INTERVAL_MIN, SEND_INTERVAL_MAX)] {
            let (l, h) = (f64::from(lo), f64::from(hi));
            for x in [
                f64::NAN,
                f64::INFINITY,
                f64::NEG_INFINITY,
                f64::MAX,
                f64::MIN,
                -0.0,
                0.0,
                l - 1.0,
                l - 0.5,
                l,
                l + f64::EPSILON * l,
                l + 0.5,
                l + 1.0,
                h - 1.0,
                h - 0.5,
                h - 1e-9,
                h,
                h + 0.5,
                h + 1.0,
            ] {
                assert_eq!(ceil_clamp(x, lo, hi), ceil_clamp_by_cast(x, lo, hi), "x = {x}");
            }
        }
    }

    #[test]
    fn ceil_clamp_matches_the_cast_formula_across_the_range() {
        // Every multiple of 1/64 from -64 to 1088 (exact in binary), around both clamp windows.
        for i in -4096..=69_632 {
            let x = f64::from(i) / 64.0;
            for (lo, hi) in [(50, 1000), (SEND_INTERVAL_MIN, SEND_INTERVAL_MAX)] {
                assert_eq!(ceil_clamp(x, lo, hi), ceil_clamp_by_cast(x, lo, hi), "x = {x}");
            }
        }
    }

    proptest::proptest! {
        #[test]
        fn ceil_clamp_matches_the_cast_formula(x in proptest::num::f64::ANY, wide in -2000.0f64..3000.0) {
            for (lo, hi) in [(50, 1000), (SEND_INTERVAL_MIN, SEND_INTERVAL_MAX)] {
                proptest::prop_assert_eq!(ceil_clamp(x, lo, hi), ceil_clamp_by_cast(x, lo, hi));
                proptest::prop_assert_eq!(ceil_clamp(wide, lo, hi), ceil_clamp_by_cast(wide, lo, hi));
            }
        }
    }
}
