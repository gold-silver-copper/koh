# Security Policy

koh is a young, largely single-maintainer project. It has had several internal security, quality, and
architecture reviews, but **no external/professional audit** — please calibrate trust accordingly (see
[`THREAT_MODEL.md`](THREAT_MODEL.md) and the README's *Public API stability* notes). `forbid(unsafe)`
and a denied-panic lint family shrink the surface that needs auditing, but they do not replace
independent eyes.

## Reporting a vulnerability

Please report suspected security issues **privately**, not in a public issue or PR:

- **Preferred:** GitHub private vulnerability reporting — open a draft advisory at
  <https://github.com/gold-silver-copper/koh/security/advisories/new>.
- **Backup:** email the maintainer at `stephen.korzen@gmail.com` with `[koh security]` in the subject.

Helpful to include: a description and impact, the affected version (`koh --version`), and a
reproduction if you have one. We aim to **acknowledge within 7 days** and to coordinate a fix and
disclosure within **90 days** of a confirmed report (sooner for an actively-exploited issue). We'll
credit reporters who want it.

## Scope

**In scope** (code koh authors):

- The passphrase PAKE handshake (`src/transport_iroh/auth.rs`) and the at-rest identity-key format
  (`src/transport_iroh/keyfile.rs`).
- The connection accept gauntlet / authorization and rate limiter (`src/server/cli.rs`,
  `src/transport_iroh/ratelimit.rs`).
- The untrusted wire decoders (`src/wire.rs`) and the SSP state machine (`src/ssp/`).
- The terminal apply path (`src/terminal/`), including the **contained** `vt100` parser surface.
- On-disk identity-key handling and local-attacker hardening (`src/transport_iroh/`).

**Out of scope — report upstream** (dependencies koh does not author):

- Transport crypto / QUIC / TLS: **iroh** and its QUIC backend, **rustls**, **ring**.
- The terminal emulator **`vt100`** (koh *contains* its panics on the client — see `process_contained`
  — but a vt100 logic/parse bug should be reported to the `vt100` project) and the PTY layer
  **`portable-pty`**.
- Known advisories in the dependency tree are tracked via `cargo deny check advisories` (CI) +
  [`deny.toml`](deny.toml).

## Please do not

Run automated scanning that degrades a third party (relays, the public DNS discovery service), or test
against servers / keys you do not own.
