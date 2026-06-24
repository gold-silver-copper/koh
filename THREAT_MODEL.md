# koh threat model

A map of who koh defends against, the trust boundaries, the properties it provides, and — as
importantly — what it explicitly does **not** try to do. This exists so a reviewer knows where to
look; pair it with [`SECURITY.md`](SECURITY.md).

## What koh is

A mosh-like remote shell over [iroh](https://iroh.computer) (peer-to-peer QUIC). The **server** spawns
a real shell in a PTY and streams terminal state to a **client** via a mosh-style state-sync protocol.
There is **no listening port**: a server is reachable only via its non-enumerable Ed25519 **node-id**
(through relays + NAT hole-punching), and only peers on its **allowlist** are admitted. It is a
**single-operator** tool for connecting a small set of machines you control — not a multi-user network
service.

## Attacker models

1. **Malicious / compromised client** — a peer that dials the server. Pre-auth it can send handshake
   bytes (stall, malformed/garbage PAKE, downgrade attempts). If it is on the allowlist *and* knows
   the passphrase (or none is set) it reaches the SSP data plane and sends arbitrary UserInput / Resize
   / fragmented instructions. **Goal it must be denied:** crash / OOM / hang the server, bypass a cap,
   or escape the admission gauntlet. The server is the high-value target (it runs a shell).
2. **Malicious / compromised server** — a server a client dials (a wrong/typo'd node-id, or a popped
   host). It sends arbitrary screen-state instructions + out-of-band data (title/icon/bell/clipboard).
   **Goal it must be denied:** crash / OOM / hang the client, impersonate a trusted server *without*
   the passphrase, or downgrade auth to none. (It can, of course, mislead a user who chose to connect
   to it — that is inherent.)
3. **Network / MITM** — QUIC + TLS 1.3 (via iroh) give transport encryption and node-id
   authentication. Considered: auth downgrade, replay, and whether any handshake transcript is
   offline-crackable against the passphrase.
4. **Local attacker** — another uid on the same host. Targets: the identity key file, the state dir,
   the passphrase in env/argv/logs, signals to a recycled pid, temp files.

## Trust boundaries & key defenses

- **Peer identity:** both ends are authenticated by Ed25519 node-id *by construction* (no TOFU
  window). Authorization is an explicit **allowlist** (off-list peers refused). An **optional** second
  factor is a balanced **SPAKE2 PAKE** (Argon2id, mutual key confirmation, no offline-crackable
  transcript; per-peer online rate limiter). The accept gauntlet (`src/server/cli.rs`) is the
  trust-boundary checkpoint; its outcomes are logged structured under the `koh::auth` target. An
  admitted peer can be further constrained per node-id (`--allow-file`): **read-only** (`restrict` —
  input dropped before the PTY, a real boundary) and/or a **forced command** (sshd-style
  `ForceCommand`; in koh's single-uid model a soft restriction, not a jail — see non-goals).
- **Untrusted data plane:** the SSP core (`src/ssp/`, `src/wire.rs`) is a pure, panic-free-by-
  construction state machine with per-direction decode/inflate ceilings, a fragment replay gate, a
  reassembly byte cap, an accumulation budget, and dimension clamps before any vt100 allocation. The
  `vt100` escape parser (a dependency outside koh's no-panic coverage) is wrapped in `catch_unwind`
  on the client so a crafted server repaint drops a frame instead of crashing the session.
- **Process / local:** `forbid(unsafe)` crate-wide; identity key written `0600` (born-private atomic
  write, `O_NOFOLLOW` read, fd-based perm-tighten) and **optionally encrypted at rest** (Argon2id +
  AES-256-GCM; see `koh key`); passphrase carried as a redacted/zeroized `SecretString`; `KOH_*` env
  scrubbed before exec'ing the shell; PTY kill gated against pid reuse.

The detailed finding history (security audit + the K-/AR-/CR- review series) lives in the git log and
the inline `KOH-`/`KR-`/`K-`/`AR-` rationale tags.

## Non-goals (where koh does NOT match a hardened multi-user service)

- **No privilege separation / multi-user model:** the shell runs as the uid that ran `koh serve`;
  there is no per-user mapping, PAM, or chroot. Per-node-id authorization *does* exist
  (`--allow-file`: read-only `restrict` + a `ForceCommand`-style forced command), but in this
  single-uid world a forced command is a soft restriction, not a sandbox — **read-only** is the
  only one of the two that is a hard boundary (the input is dropped before it can reach the shell).
- **No hardware-backed / certificate / agent identity:** the node-id key lives on disk (optionally
  passphrase-encrypted, but not in an HSM / FIDO2 token / agent).
- **No post-quantum key exchange yet:** transport crypto is inherited from iroh; koh is a policy-taker.
- **Transport crypto is not koh's:** QUIC/TLS/KEX correctness is iroh/rustls/ring's responsibility.
- **Not a substitute for ssh** where independent audit, compliance, or a multi-user/jail model is
  required — see the README's comparison.
