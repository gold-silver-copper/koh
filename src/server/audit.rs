//! Structured auth-event logging — sshd-style.
//!
//! `sshd` emits one greppable line per admission outcome with a stable status token + peer + reason
//! ("Accepted publickey for USER from IP port N", "Failed ...", "Connection closed ... (preauth)"),
//! which SIEM/fail2ban consume. koh already logs at every accept-gauntlet node, but as free-text
//! messages. This gives the security-relevant admission/auth decisions a STABLE machine schema —
//! always the same fields (`event`, `outcome`, `peer`, `reason`) under the `koh::auth` log target, at
//! a level keyed by outcome — so a consumer matches a field (or filters `RUST_LOG=koh::auth=info`),
//! not brittle prose. Inspired by OpenSSH's `auth.c` `auth_log()` (one fixed line per outcome with a
//! stable status token + peer identity + reason).

use iroh::EndpointId;

/// The admission outcome — the stable status token, mirroring sshd's Accepted/Refused.
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

/// Emit one structured authorization event with the stable schema (`event`, `outcome`, `peer`,
/// `reason`) under the `koh::auth` target. `event` is always `authz` (the only admission gate is the
/// allowlist); it stays in the schema so a consumer's filter is stable if more event kinds appear.
/// INFO for an accepted outcome, WARN for a denial. `peer` is the node-id hex (always known: the
/// QUIC/TLS handshake authenticates it before any admission decision).
pub fn auth_event(outcome: Outcome, peer: &EndpointId, reason: &str) {
    let peer = crate::transport_iroh::format_endpoint_id(peer);
    if matches!(outcome, Outcome::Accepted) {
        tracing::info!(target: "koh::auth", event = "authz", outcome = outcome.token(), peer = %peer, reason);
    } else {
        tracing::warn!(target: "koh::auth", event = "authz", outcome = outcome.token(), peer = %peer, reason);
    }
}
