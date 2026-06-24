//! Per-node-id authorization policy (the `--allow-file`).
//!
//! koh's baseline authorization is the node-id allowlist (`--allow`): a peer is admitted or it is
//! not. This module adds *per-peer* policy on top, modeled on sshd's `authorized_keys` options and
//! `ForceCommand`:
//!
//! - **`restrict`** — read-only. The peer can watch the live shell but its keystrokes and resizes
//!   never reach the PTY (enforced in [`run_attached`](crate::server::run_attached)). This is a real
//!   boundary: the input is dropped before it can drive the shell.
//! - **`command="…"`** — a forced command run via the login shell's `-c` instead of an interactive
//!   session (sshd's `ForceCommand`). Useful for pinning a peer to e.g. `tmux attach`. Note koh is a
//!   **single-uid** tool, so — unlike sshd behind a uid boundary — a forced command is a
//!   *convenience / soft restriction*, not a jail: a command that can spawn a subshell (an editor's
//!   `:!sh`, a pager, …) escapes it. Pair it with `restrict` and a command that can't shell out for
//!   anything resembling confinement.
//!
//! The file is read once at startup. Format: one entry per line,
//! `<endpoint-id> [restrict] [command="…"]`; `#` comments and blank lines are ignored. Options may
//! appear in any order; `restrict` may sit before or after `command=`.

use std::collections::HashSet;
use std::path::Path;

use anyhow::{bail, Context, Result};
use iroh::EndpointId;

use crate::transport_iroh::parse_endpoint_id;

/// The authorization policy resolved for one peer. The default (`--allow <id>` with no options) is a
/// full read-write interactive shell.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    /// Drop the peer's input: it can observe the shell but not type into or resize it.
    pub read_only: bool,
    /// Run this command via the login shell's `-c` instead of an interactive session.
    pub force_command: Option<String>,
}

/// Parse one non-comment, non-blank allow-file line's option list (everything after the id) into a
/// [`Policy`]. Kept separate from id parsing so it is trivially unit-testable.
fn parse_options(rest: &str) -> Result<Policy> {
    let mut policy = Policy::default();

    // `command="…"` is extracted first because its value can contain spaces (and even the substring
    // `restrict`), so it must not be word-split like the bare options around it.
    if let Some((before, after)) = rest.split_once("command=") {
        let (cmd, tail) = if let Some(quoted) = after.strip_prefix('"') {
            match quoted.split_once('"') {
                Some((inner, tail)) => (inner.to_string(), tail),
                None => bail!("unterminated quoted command=\"…\""),
            }
        } else {
            // Unquoted: the remainder of the line is the command. No trailing options are supported
            // after an unquoted command (quote it if you also need `restrict` after it).
            (after.trim().to_string(), "")
        };
        if cmd.is_empty() {
            bail!("empty command= (drop it for an interactive shell)");
        }
        policy.force_command = Some(cmd);
        for tok in before.split_whitespace().chain(tail.split_whitespace()) {
            parse_bare_option(tok, &mut policy)?;
        }
    } else {
        for tok in rest.split_whitespace() {
            parse_bare_option(tok, &mut policy)?;
        }
    }

    Ok(policy)
}

/// Apply one whitespace-delimited bare option token to `policy`, rejecting anything unknown so a
/// typo (`restict`) fails loudly at startup rather than silently granting more than intended.
fn parse_bare_option(tok: &str, policy: &mut Policy) -> Result<()> {
    match tok {
        "restrict" => policy.read_only = true,
        other => {
            bail!("unknown allow-file option {other:?} (expected `restrict` or `command=\"…\"`)")
        }
    }
    Ok(())
}

/// Parse the full contents of an allow-file into `(id, policy)` pairs.
///
/// A duplicate endpoint id is an error (almost always a copy-paste mistake), as is any malformed id
/// or unknown option — the server fails to start rather than silently authorizing the wrong thing.
pub fn parse_allow_file(contents: &str) -> Result<Vec<(EndpointId, Policy)>> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for (lineno, raw) in contents.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (id_str, rest) = line
            .split_once(|c: char| c.is_whitespace())
            .unwrap_or((line, ""));
        let one = lineno.saturating_add(1);
        let id = parse_endpoint_id(id_str)
            .with_context(|| format!("allow-file line {one}: bad endpoint id {id_str:?}"))?;
        if !seen.insert(id) {
            bail!("allow-file line {one}: duplicate endpoint id {id_str:?}");
        }
        let policy =
            parse_options(rest).with_context(|| format!("allow-file line {one}: bad options"))?;
        out.push((id, policy));
    }
    Ok(out)
}

/// Read and parse an allow-file from disk.
pub fn load_allow_file(path: &Path) -> Result<Vec<(EndpointId, Policy)>> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("reading allow-file {}", path.display()))?;
    parse_allow_file(&contents)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A syntactically valid 64-hex endpoint id (all-zero key) for parser tests.
    const ID0: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    const ID1: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    #[test]
    fn bare_id_is_full_access() {
        let p = parse_allow_file(ID0).expect("parse");
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].1, Policy::default());
    }

    #[test]
    fn restrict_sets_read_only() {
        let p = parse_allow_file(&format!("{ID0} restrict")).expect("parse");
        assert!(p[0].1.read_only);
        assert!(p[0].1.force_command.is_none());
    }

    #[test]
    fn quoted_command_keeps_spaces() {
        let p = parse_allow_file(&format!("{ID0} command=\"tmux attach -t main\"")).expect("parse");
        assert_eq!(p[0].1.force_command.as_deref(), Some("tmux attach -t main"));
        assert!(!p[0].1.read_only);
    }

    #[test]
    fn restrict_and_command_compose_either_order() {
        let a = parse_allow_file(&format!("{ID0} restrict command=\"top\"")).expect("parse a");
        let b = parse_allow_file(&format!("{ID1} command=\"top\" restrict")).expect("parse b");
        assert!(a[0].1.read_only && a[0].1.force_command.as_deref() == Some("top"));
        assert!(b[0].1.read_only && b[0].1.force_command.as_deref() == Some("top"));
    }

    #[test]
    fn comments_and_blanks_ignored() {
        let src = format!("# header\n\n  {ID0}  \n# trailing\n{ID1} restrict\n");
        let p = parse_allow_file(&src).expect("parse");
        assert_eq!(p.len(), 2);
    }

    #[test]
    fn unquoted_command_takes_rest_of_line() {
        let p = parse_allow_file(&format!("{ID0} command=/usr/bin/uptime")).expect("parse");
        assert_eq!(p[0].1.force_command.as_deref(), Some("/usr/bin/uptime"));
    }

    #[test]
    fn unknown_option_is_rejected() {
        assert!(parse_allow_file(&format!("{ID0} restict")).is_err());
    }

    #[test]
    fn unterminated_quote_is_rejected() {
        assert!(parse_allow_file(&format!("{ID0} command=\"oops")).is_err());
    }

    #[test]
    fn empty_command_is_rejected() {
        assert!(parse_allow_file(&format!("{ID0} command=\"\"")).is_err());
    }

    #[test]
    fn bad_id_is_rejected() {
        assert!(parse_allow_file("not-a-valid-id restrict").is_err());
    }

    #[test]
    fn duplicate_id_is_rejected() {
        assert!(parse_allow_file(&format!("{ID0}\n{ID0} restrict")).is_err());
    }
}
