//! RTT/RTO estimation.
//!
//! Under iroh, quinn already measures a smoothed path RTT (`Connection::rtt()`). We feed
//! those samples into mosh's own Jacobson/Karels estimator so the send scheduler keeps
//! mosh's exact `send_interval()` ("two frames per RTT") and `timeout()` (RTO) behavior.
//! Using these instead of raw quinn RTT keeps the timer math identical to upstream mosh.

use tracing::trace;

use crate::{SEND_INTERVAL_MAX, SEND_INTERVAL_MIN};

/// Smoothed RTT / RTO estimator (mosh `Network::Connection` initial values + update rule).
#[derive(Debug, Clone)]
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
        RttEstimator {
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
        if !self.hit {
            self.srtt = r_ms;
            self.rttvar = r_ms / 2.0;
            self.hit = true;
        } else {
            self.rttvar = 0.75 * self.rttvar + 0.25 * (self.srtt - r_ms).abs();
            self.srtt = 0.875 * self.srtt + 0.125 * r_ms;
        }
        trace!(
            sample = r_ms,
            srtt = self.srtt,
            rttvar = self.rttvar,
            "rtt sample"
        );
    }

    /// Smoothed RTT in milliseconds.
    pub fn srtt_ms(&self) -> f64 {
        self.srtt
    }

    /// Retransmission timeout (RTO), `clamp(ceil(SRTT + 4·RTTVAR), 50, 1000)` ms.
    pub fn timeout(&self) -> u64 {
        let rto = (self.srtt + 4.0 * self.rttvar).ceil() as i64;
        rto.clamp(50, 1000) as u64
    }

    /// Inter-frame send interval, `clamp(ceil(SRTT / 2), 20, 250)` ms ("two frames per RTT").
    pub fn send_interval(&self) -> u64 {
        let si = (self.srtt / 2.0).ceil() as i64;
        si.clamp(SEND_INTERVAL_MIN as i64, SEND_INTERVAL_MAX as i64) as u64
    }
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
        assert_eq!(e.srtt_ms(), before);
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
        assert_eq!(
            e.srtt_ms(),
            srtt,
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
            e.srtt_ms(),
            srtt,
            "a changed sample still updates the estimate"
        );
    }
}
