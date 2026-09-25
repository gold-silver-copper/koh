# Security Policy

koh is a young, largely single-maintainer project. It has had several internal security, quality, and
architecture reviews, but **no external/professional audit** — please calibrate trust accordingly (see
the [`THREAT_MODEL.md`](docs/THREAT_MODEL.md)). `forbid(unsafe)` and a denied-panic lint family shrink
the surface that needs auditing, but they do not replace independent eyes.

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

- On-disk identity-key handling and local-attacker hardening (`koh-core/src/transport_iroh/`,
  `koh-core/src/identity.rs`): the key file is the raw 32-byte secret, protected by its
  permissions (0600) like an SSH host key.
- The connection accept gauntlet / node-id allowlist authorization
  (`koh-core/src/server/cli.rs`) and the admission barrier
  (`koh-core/src/transport_iroh/admission.rs`).
- The untrusted wire decoders (`koh-core/src/proto.rs`) and the connection cores
  (`koh-core/src/server/mod.rs`, `koh-core/src/client/session.rs`).
- The terminal apply path (`koh-core/src/terminal/`): decoding and validating the structured screen diff.

**Out of scope — report upstream** (dependencies koh does not author):

- Transport crypto / QUIC / TLS: **iroh** and its QUIC backend, **rustls**, **ring**.
- The server's terminal emulator **`fux-vt`** (a parse/logic bug belongs to the
  [fux](https://github.com/gold-silver-copper/fux) project; the client never runs it on server
  bytes) and the PTY layer **`portable-pty`**.
- Known advisories in the dependency tree are tracked via `cargo deny check advisories` (CI) +
  [`deny.toml`](deny.toml).

## Please do not

Run automated scanning that degrades a third party (relays, the public DNS discovery service), or test
against servers / keys you do not own.
