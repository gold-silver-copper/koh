# Changelog

All notable changes to koh are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and koh aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) for the **binary's CLI, the on-disk
`koh-key-v1` key format, and the wire `PROTOCOL_VERSION`/ALPN**. The library crate is binary-first and
its API is internal and unstable (see the README).

> **A note on versions.** [crates.io](https://crates.io/crates/koh) is the source of truth for what
> was actually released. Two git-tag-only gaps exist from koh's early, fast-moving security-review
> period: **v0.4.0–v0.4.3** were tagged during a rapid follow-up series but superseded by **0.4.4**
> before publishing, and **v0.6.0** (encrypted-at-rest keys, vt100 containment, per-node-id authz) was
> developed and folded into **0.7.0** rather than released on its own. Published versions:
> 0.1.0–0.3.2, 0.4.4, 0.5.0, 0.7.0.

## [Unreleased]

The next release consolidates a large security/minimalism pass. It is **breaking** (flags, env vars,
and the default key location changed).

### Removed
- **`--allow-any`** — there is no "accept any peer" mode; at least one `--allow <id>` is required, so a
  stray `koh serve` can never publish an open shell.
- **`--read-only`** — the observer mode is gone; the node-id allowlist is the sole access control.
- **`--allow-file` / per-peer authorization** and three low-value config knobs; the clipboard handling
  was consolidated.
- **`$KOH_STATE_DIR`** and the `directories` dependency.

### Changed
- **All koh-owned files now live under `~/.config/koh` only** (`$XDG_CONFIG_HOME/koh` is honored).
  Removed the platform-specific dir (macOS *Application Support*) and every `/tmp` / `/data/local/tmp`
  / CWD fallback; koh now errors rather than scattering a key when `~/.config` can't be located
  (`--key-file` remains the explicit override).
- **Identity-key hardening:** passphrase floor raised from 8 to **12 characters**, and Argon2id
  `t_cost` 3 → 4 (both apply to newly-written keys only; existing keys still decrypt).
- **Stricter builds:** `overflow-checks = true` in release, `dead_code = "deny"`.

### Added
- Property tests for the attacker-reachable parsers (`Transport::recv`, `FragmentAssembly::add`,
  `decrypt_key`); the terminal parser rebuild now runs through the vt100 panic-containment path.
- Release/maturity tooling: a `COPYING` (GPL-3.0) license file, this changelog, and CI that verifies
  the MSRV, builds on macOS, and treats clippy warnings as errors.

### Fixed
- Idle empty-ack flood (an idle side re-sent an empty ack every ~100 ms instead of settling onto the
  3 s keepalive); the prediction engine now resets its byte decoder on resize; redundant server-side
  re-snapshots on the input path.

## [0.7.0] — 2026-06-25
- **Removed the SPAKE2/PAKE passphrase second factor.** Identity keys are now **always encrypted at
  rest** (`koh-key-v1`: Argon2id + AES-256-GCM), and authorization is the node-id allowlist alone. Also
  ships the prior 0.6.0 work: vt100 panic containment on both sides and per-node-id authorization.

## [0.5.0] — 2026-06-24
- Architectural review follow-ups: a pure, I/O-free `ServerSession` core; required per-state DoS bounds
  (`RECV_DECODE_LIMIT` / `RECEIVE_BUDGET_UNITS`); RAII attach guards; a CI layering guard.

## [0.4.4] — 2026-06-24
- Engineering-quality pass: fuzz targets + property tests on the untrusted decoders, an idle-snapshot
  gate, CI + `cargo-deny`, and docs. Supersedes the unpublished 0.4.0–0.4.3 interim security fixes.

## [0.3.2] — 2026-06-23
- Security-audit hardening of the post-auth data plane (inflation / reassembly / accumulation caps) and
  a screen-off reconnect fix.

## [0.3.1] — 2026-06-23
- Hardening against hostile or compromised peers (transport-level fixes).

## [0.3.0] — 2026-06-23
- Detachable/reattachable sessions, terminal-reply synthesis (DSR/DA/DECRQM), remote exit-status
  propagation, and the opt-in Android-emulator test suite.

## [0.2.0] — 2026-06-23
- Early iteration of the transport + terminal core.

## [0.1.0] — 2026-06-23
- Initial release: the SSP protocol core, the terminal model, the PTY host, the local-echo predictor,
  and the iroh QUIC transport.

[Unreleased]: https://github.com/gold-silver-copper/koh/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/gold-silver-copper/koh/releases/tag/v0.7.0
[0.5.0]: https://github.com/gold-silver-copper/koh/releases/tag/v0.5.0
[0.4.4]: https://github.com/gold-silver-copper/koh/releases/tag/v0.4.4
[0.3.2]: https://github.com/gold-silver-copper/koh/releases/tag/v0.3.2
[0.3.1]: https://github.com/gold-silver-copper/koh/releases/tag/v0.3.1
[0.3.0]: https://github.com/gold-silver-copper/koh/releases/tag/v0.3.0
[0.2.0]: https://github.com/gold-silver-copper/koh/releases/tag/v0.2.0
[0.1.0]: https://github.com/gold-silver-copper/koh/releases/tag/v0.1.0
