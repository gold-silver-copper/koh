//! Admission decisions as structured events, as sshd logs them: always the fields `event`,
//! `outcome`, `peer` and `reason` under the `koh::auth` target. There is no address to ban: a peer
//! may come through a relay, and a new endpoint id costs nothing, so the allowlist is the gate.

use iroh::EndpointId;

/// The admission outcome, as sshd's Accepted and Refused.
#[derive(Clone, Copy)]
pub enum Outcome {
    /// The peer passed the gate: its node-id is on the allowlist.
    Accepted,
    /// Rejected by policy: not on the allowlist.
    Rejected,
}

impl Outcome {
    const fn token(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
        }
    }
}

/// Log one admission decision: info if accepted, warn if not. `event` is always `authz`, kept so
/// filters survive new kinds.
pub fn auth_event(outcome: Outcome, peer: &EndpointId, reason: &str) {
    if matches!(outcome, Outcome::Accepted) {
        tracing::info!(target: "koh::auth", event = "authz", outcome = outcome.token(), peer = %peer, reason);
    } else {
        tracing::warn!(target: "koh::auth", event = "authz", outcome = outcome.token(), peer = %peer, reason);
    }
}

/// A warning said at most once every ten seconds, however often its cause comes: a flood would
/// say it at the flood's rate.
#[derive(Default)]
pub struct Throttle(std::sync::Mutex<Option<std::time::Instant>>);

impl Throttle {
    /// Whether to say it now: the first time, then once ten seconds have passed since it was.
    pub fn ready(&self) -> bool {
        let (Ok(mut said), now) = (self.0.lock(), std::time::Instant::now()) else {
            return false;
        };
        let ready = said.is_none_or(|at| now.saturating_duration_since(at).as_secs() >= 10);
        ready.then(|| *said = Some(now)).is_some()
    }
}

#[cfg(test)]
#[test]
fn a_flood_of_turned_away_peers_is_said_once() {
    let throttle = Throttle::default();
    assert_eq!((0..1000).filter(|_| throttle.ready()).count(), 1);
}
