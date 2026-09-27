//! Admission decisions as structured events, as sshd logs them: always the fields `event`,
//! `outcome`, `peer` and `reason` under the `koh::auth` target, so fail2ban and the like match
//! fields, not prose.

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
