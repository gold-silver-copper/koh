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

/// The admission/auth outcome — the stable status token, mirroring sshd's Accepted/Failed/Postponed.
#[derive(Clone, Copy)]
pub(crate) enum Outcome {
    /// The peer passed this gate (authorized).
    Accepted,
    /// Rejected by policy: not on the allowlist, or rate-limited.
    Rejected,
    /// An explicit auth failure (wrong/missing passphrase) — counts toward the rate limiter.
    Failed,
    /// The handshake timed out (a transient/network outcome, NOT counted as a guess; see K-07).
    Timeout,
}

impl Outcome {
    const fn token(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Failed => "failed",
            Self::Timeout => "timeout",
        }
    }
}

/// Emit one structured auth/admission event with the stable schema (`event`, `outcome`, `peer`,
/// `reason`) under the `koh::auth` target. INFO for an accepted outcome, WARN for the rest (the
/// security-relevant denials). `peer` is the node-id hex, or `-` if unknown.
pub(crate) fn auth_event(event: &str, outcome: Outcome, peer: Option<&EndpointId>, reason: &str) {
    let peer = peer.map_or_else(|| "-".to_owned(), crate::transport_iroh::format_endpoint_id);
    if matches!(outcome, Outcome::Accepted) {
        tracing::info!(target: "koh::auth", event, outcome = outcome.token(), peer = %peer, reason);
    } else {
        tracing::warn!(target: "koh::auth", event, outcome = outcome.token(), peer = %peer, reason);
    }
}
