# Security Policy

koh is a young, largely single-maintainer project. It has had several internal security, quality, and
architecture reviews, but **no external/professional audit** — please calibrate trust accordingly (see
the [`THREAT_MODEL.md`](docs/THREAT_MODEL.md)). `forbid(unsafe)` and the forbidden panic lints shrink
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

- On-disk identity-key handling and local-attacker hardening (`src/identity.rs`,
  `src/identity/key_file.rs`): the key file is the raw 32-byte secret, protected by its
  permissions (0600) like an SSH host key.
- The connection accept gauntlet / client-key allowlist authorization (`src/server/cli.rs`),
  and the proof of a client's key on each connection (`src/transport_iroh/mod.rs`, `prove` and
  `proven`), and the session registry that attaches only allowed peers
  (`src/server/session/sessions.rs`).
- The untrusted wire decoders (`src/proto.rs`, `src/request.rs`, `src/sync/`) and the connection
  cores (`src/server/attach.rs`, `src/client/mod.rs`).
- The output filter both ends run (`src/stream.rs`): what of a server's output reaches the
  user's terminal.
- What a request may reach on the server: the scopes of client keys (`src/server/cli.rs`,
  `src/server/place.rs`), and where a copy lands (`src/sync/receive.rs`, `src/sync/fsat.rs`).

**Out of scope — report upstream** (dependencies koh does not author):

- Transport crypto / QUIC / TLS: **iroh** and its QUIC backend, **rustls**, **ring**.
- The terminal emulator **`fux-vt`**, which the server runs on its programs' output and the
  client on what it writes to the user's terminal (a parse/logic bug belongs to the
  [fux](https://github.com/gold-silver-copper/fux) project), and the system-call layer **`fuxix`** (PTYs, each session's `setsid` and
  controlling terminal, signals; also fux's).
- Known advisories in the dependency tree are tracked via `cargo deny check advisories` (CI) +
  [`deny.toml`](deny.toml).

## Past audits

koh's earlier security audits and reviews, and what fixed each finding, are in the git history
(their PRs and commits). The tests that guard the fixes say so in their names and comments.

## Please do not

Run automated scanning that degrades a third party (relays, the public DNS discovery service), or test
against servers / keys you do not own.
