# koh threat model

A map of who koh defends against, the trust boundaries, the properties it provides, and — as
importantly — what it explicitly does **not** try to do. This exists so a reviewer knows where to
look; pair it with [`SECURITY.md`](../SECURITY.md).

## What koh is

A mosh-like remote shell over [iroh](https://iroh.computer) (peer-to-peer QUIC). The **server** spawns
a real shell in a PTY and sends its screen to a **client** as frames over QUIC streams.
There is **no listening port**: a server is reachable only via its non-enumerable Ed25519 **node-id**
(through relays + NAT hole-punching), and only peers on its **allowlist** are admitted. It is a
**single-operator** tool for connecting a small set of machines you control — not a multi-user network
service.

## Attacker models

1. **Malicious / compromised client** — a peer that dials the server. If it is on the allowlist it
   reaches the koh/3 data plane: it sends arbitrary input, resize, ack and resync messages and opens
   streams.
   **Goal it must be denied:** crash / OOM / hang the server, bypass a cap, or escape the admission
   gauntlet. The server is the high-value target (it runs a shell).
2. **Malicious / compromised server** — a server a client dials (a wrong/typo'd node-id, or a popped
   host). It sends arbitrary screen-state instructions + out-of-band data (title/icon/bell/clipboard).
   **Goal it must be denied:** crash / OOM / hang the client. It *can* mislead a user who chose to
   connect to it — that is inherent, and with no second factor the node-id is the only thing tying a
   session to a specific server, so node-ids should be verified out-of-band.
3. **Network / MITM** — QUIC + TLS 1.3 (via iroh) give transport encryption and node-id
   authentication by construction (no TOFU window). Considered: replay, and connection-level tamper.
4. **Local attacker** — another uid on the same host. Targets: the (encrypted) identity key file and
   its passphrase, the state dir, signals to a recycled pid, temp files.

## Trust boundaries & key defenses

- **Peer identity:** both ends are authenticated by Ed25519 node-id *by construction* (no TOFU
  window). Authorization is an explicit **allowlist** (off-list peers refused); at least one entry is
  required, so there is no "accept any peer" mode. This is the **single** authentication factor —
  there is no passphrase/PAKE second factor (the residual leaked-key risk is handled by mandatory
  at-rest key encryption, below). The accept gauntlet (`src/server/cli.rs`) is the trust-boundary
  checkpoint; its outcomes are logged structured under the `koh::auth` target.
- **Untrusted data plane:** the protocol (`src/proto.rs`) and the connection cores
  (`src/server/mod.rs`, `src/client/session.rs`) are pure and panic-free by construction. Client
  messages are length-capped (64 KiB of input each) and a frame is read and inflated with a 16 MiB
  limit; each end keeps a fixed window of 16 screens, whatever the peer sends or withholds; QUIC
  stream limits and flow control bound what a peer can have in flight; and resize dimensions are
  clamped before any grid allocation.
  **The client runs no terminal parser on server bytes:** a screen update is a structured diff of
  whole rows of run-length-encoded cells, which `TerminalScreen::apply` validates completely (row
  indices, runs covering exactly the width, known cell kinds and style bits, cell text within the
  emulator's per-cell cap, known modes) before committing; a malformed frame is dropped whole. The
  server's emulator is `fux-vt`, which is panic-free by construction (its own `forbid` lints) and
  bounded: it retains no DCS/APC/PM/SOS payload and caps an OSC string at 64 KiB, so a runaway
  control string from the shell can't grow memory. koh therefore no longer wraps the emulator in
  `catch_unwind` or pre-filters control strings.
- **Process / local:** `forbid(unsafe)` crate-wide; identity key written `0600` (born-private atomic
  write, `O_NOFOLLOW` read, fd-based perm-tighten) and **always encrypted at rest** (Argon2id +
  AES-256-GCM, `koh-key-v1`; no plaintext format, and a minimum passphrase length is enforced so an
  *effectively* unencrypted key can't be created); its passphrase carried as a redacted/zeroized
  `SecretString`; `KOH_*` env scrubbed before exec'ing the shell; PTY kill gated against pid reuse.
  Note at-rest encryption only protects a stolen key if `$KOH_KEY_PASSPHRASE` is not stored beside it.

The detailed finding history (security audit + the K-/AR-/CR- review series) lives in the git log and
the inline `KOH-`/`KR-`/`K-`/`AR-` rationale tags.

## Non-goals (where koh does NOT match a hardened multi-user service)

- **No privilege separation / multi-user model:** the shell runs as the uid that ran `koh serve`;
  there is no per-user mapping, PAM, chroot, or `ForceCommand`-class policy. The only access control
  is the node-id allowlist; access is uniform across allowed peers.
- **No hardware-backed / certificate / agent identity:** the node-id key lives on disk (always
  passphrase-encrypted, but not in an HSM / FIDO2 token / agent).
- **No post-quantum key exchange yet:** transport crypto is inherited from iroh; koh is a policy-taker.
- **Transport crypto is not koh's:** QUIC/TLS/KEX correctness is iroh/rustls/ring's responsibility.
- **Not a substitute for ssh** where independent audit, compliance, or a multi-user/jail model is
  required — see the README's comparison.
