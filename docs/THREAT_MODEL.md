# koh threat model

A map of who koh defends against, the trust boundaries, the properties it provides, and — as
importantly — what it explicitly does **not** try to do. This exists so a reviewer knows where to
look; pair it with [`SECURITY.md`](../SECURITY.md).

## What koh is

A mosh-like remote shell over [iroh](https://iroh.computer) (peer-to-peer QUIC). The **server** spawns
a real shell in a PTY and streams terminal state to a **client** via a mosh-style state-sync protocol.
There is **no listening port**: a server is reachable only via its non-enumerable Ed25519 **node-id**
(through relays + NAT hole-punching), and only peers on its **allowlist** are admitted. It is a
**single-operator** tool for connecting a small set of machines you control — not a multi-user network
service.

## Attacker models

1. **Malicious / compromised client** — a peer that dials the server. If it is on the allowlist it
   reaches the SSP data plane and sends arbitrary UserInput / Resize / fragmented instructions.
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
  required, so there is no "accept any peer" mode. The node-id allowlist is the default (and, without
  the opt-in below, the sole) authentication factor; the residual leaked-key risk is handled by
  mandatory at-rest key encryption (below). The accept gauntlet (`src/server/cli.rs`) is the
  trust-boundary checkpoint; its outcomes are logged structured under the `koh::auth` target
  (`event = "authz"` for the allowlist, `event = "authn"` for the security-key factor).
- **Optional FIDO2 security-key second factor (`--require-sk`):** an operator can require every client
  to *also* prove possession of an allowlisted hardware security key (an OpenSSH
  `sk-ssh-ed25519@openssh.com` or `sk-ecdsa-sha2-nistp256@openssh.com` credential) before admission.
  After the allowlist check but **before**
  the admission ack — and therefore before any `session::attach`, PTY spawn, or terminal I/O — the
  server issues a fresh per-connection challenge; the client signs it with its security key (via
  `ssh-agent`, which drives the hardware touch) and returns the OpenSSH signature. koh verifies the
  signature (`ed25519-dalek` `verify_strict` for ed25519-sk, `p256::ecdsa` for ecdsa-sk — no
  home-grown crypto) and **requires the
  user-presence/touch flag**. The signed transcript (`transport_iroh::sk_auth::build_transcript`)
  length-prefixes and binds the label `koh-sk-v1`, the ALPN, the version, **both** endpoint ids, and
  the nonce, so a proof cannot be **replayed** onto another connection (fresh nonce → different
  transcript) nor **relayed** to a different server (server id is bound). The wire is small, bounded,
  and versioned; a failed/absent proof closes the connection with a clear reason. Verification lives
  in `transport_iroh::sk_auth` with its own unit + real-iroh e2e tests. **Limitations:** koh does not
  exchange a FIDO **attestation**, so it proves key possession + a touch, not that the key is genuinely
  hardware-backed — enrol only public keys you generated on real hardware. `ed25519-sk` and `ecdsa-sk`
  (P-256) are verified; other sk curves (P-384/P-521) are rejected. A signature *counter* regression
  (cloned-token detection) is not tracked across connections. This factor protects the **server** from
  an attacker holding only a leaked node-id key; it does not protect a client from a malicious server.
- **Untrusted data plane:** the SSP core (`src/ssp/`, `src/wire.rs`) is a pure, panic-free-by-
  construction state machine with per-direction decode/inflate ceilings, a fragment replay gate, a
  reassembly byte cap, an accumulation budget, and dimension clamps before any vt100 allocation. The
  `vt100` escape parser (a dependency outside koh's no-panic coverage) is wrapped in `catch_unwind`
  on **both** sides — the client (so a crafted server repaint drops a frame instead of crashing the
  session) and, as defense-in-depth, the server emulator processing shell output.
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
- **No hardware-backed *primary* identity:** the node-id key lives on disk (always
  passphrase-encrypted, but not in an HSM / FIDO2 token). A hardware key can be required as an
  *optional second factor* (`--require-sk`, above), but the node-id itself is still a disk key. There
  is no X.509 / SSH-certificate identity.
- **No post-quantum key exchange yet:** transport crypto is inherited from iroh; koh is a policy-taker.
- **Transport crypto is not koh's:** QUIC/TLS/KEX correctness is iroh/rustls/ring's responsibility.
- **Not a substitute for ssh** where independent audit, compliance, or a multi-user/jail model is
  required — see the README's comparison.
