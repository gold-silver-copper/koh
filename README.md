# koh — mosh, rewritten in Rust over iroh

`koh` is a from-scratch Rust reimplementation of [mosh](https://mosh.org) (the mobile shell) whose
transport is **[iroh](https://iroh.computer) peer-to-peer QUIC** instead of mosh's UDP/OCB. You get
mosh's signature feel — instant local echo on laggy links, survival across suspend/resume and IP
changes, no head-of-line blocking — while iroh handles encryption, NAT traversal, relay fallback,
connection migration, and RTT. It's one small binary that gives you a real remote shell **by
endpoint id, with no listening port and no SSH**.

> The name nods to iroh via *Avatar*: **Koh the Face Stealer** takes you the instant you show a
> *past* expression — survival means showing only your *current* face. That's the protocol exactly:
> only the **latest** screen state is authoritative; every superseded state is collapsed and
> discarded. koh is a *state-synchronization* system, not a tunnel — if the screen changed 100 times
> in 40 ms, only the final state is sent.

## Features

- **Instant local echo** — a predictor shows your keystrokes immediately (underlined on high-RTT
  links), then confirms/corrects from the server. Password prompts get no predicted echo
  automatically.
- **Detachable, reattachable sessions** — close the lid, reconnect, your shell is right where you
  left it (keyed by your client id; no `tmux` needed for survival).
- **Transparent auto-reconnect** — the client rides out brief outages on the same connection and
  re-dials across IP changes / long screen-offs, holding the last screen under a `reconnecting…`
  banner. It never drops you back to a local prompt.
- **No head-of-line blocking** — a burst of superseded output never delays the current frame; you
  always re-sync to the screen *as it is now*, never a replayed backlog.
- **Interactive apps work** — terminal-reply synthesis (DSR/DA/DECRQM) so vim/htop/fzf behave;
  exit-status propagation so the client exits with the remote shell's code.
- **Secure by construction** — no listening port (reachable only by a non-enumerable node-id on an
  allowlist), peer authenticated by the QUIC/TLS handshake with **no TOFU**, and an identity key
  that is **always encrypted at rest**. `forbid(unsafe)`, panic-free by lint.
- **Tiny & portable** — one ~11 k-line crate, ~25 deps, runs on Linux/macOS and Android/Termux.

## Install

```sh
cargo install --git https://github.com/gold-silver-copper/koh   # or: cargo build --release
```

## Quickstart

koh authorizes by **endpoint id** (your machine's public key) — there are no passwords or accounts.

```sh
# 1. On the client, print its id (creates an encrypted identity key on first run):
koh id
#   3f9c…(64 hex)

# 2. On the server, allow that id and start (prints its own id + a scannable QR):
koh serve --allow 3f9c…

# 3. On the client, dial the server's id:
koh connect 871b…
#   connected. (Ctrl-^ then . to disconnect)
```

By default the bare id is dialed via n0's public relay + DNS discovery (works across NATs). For LAN
or a self-hosted relay:

```sh
koh serve --local --allow 3f9c…           # no relay; prints its UDP port
koh connect 871b… --direct 192.168.1.5:41234

koh serve  --relay-url https://relay.example:3340 --allow 3f9c…
koh connect 871b… --relay-url https://relay.example:3340
```

**Commands:** `koh serve` (host a shell), `koh connect <id>` (attach), `koh id` (print your id),
`koh key passwd|info` (manage the identity key's passphrase). Useful flags: `--predict
adaptive|always|never`, `--clipboard` (opt-in OSC-52), `--session-ttl-secs`,
`--max-connections`/`--max-sessions`. koh keeps its keys under `~/.config/koh/` (override a path with
`--key-file`).

**Android / Termux** works out of the box; koh pins a public DNS resolver to sidestep an Android
JNI-context panic (override with `KOH_DNS=1.1.1.1`). Run `termux-wake-lock` so the OS doesn't freeze
the process during a long screen-off.

## koh vs mosh

koh shares mosh's SSP ancestry (predictive echo, datagram state-sync, roaming) but replaces mosh's
two structural weaknesses: mosh has **no key exchange** — a single static AES-128-OCB key, printed
by `mosh-server`, shipped over a piggybacked SSH login, and left in the client's `MOSH_KEY` env var
(no forward secrecy, a second protocol in the trust path, a documented local key-theft exposure).
koh rides iroh's per-session X25519 ECDHE keys (forward secrecy by construction), authenticates the
peer by a pinned node-id with no SSH dependency, and has no session secret to leak. It also adds real
**detach/reattach** (mosh has none — `mosh-server` dies with its session). mosh still wins on
**maturity and ubiquity** (a decade of field exposure, packaged everywhere) and on inheriting SSH's
account/PAM/2FA ecosystem for free.

| | mosh | koh |
|---|---|---|
| Transport crypto | AES-128-OCB, one **static** key | iroh QUIC + TLS 1.3, per-session AEAD |
| Forward secrecy / rekey | none | yes (X25519 ECDHE per session) |
| Bootstrap | requires an SSH login each time | self-contained; no SSH, no listening port |
| Session secret at client | AES key in `MOSH_KEY` env | none (and `KOH_*` scrubbed from the shell) |
| Detach / reattach | none (use tmux) | native, per-peer |
| Identity at rest | none persistent | one key, always encrypted |
| Maturity / ubiquity | **mature, everywhere** | young, single-maintainer, unaudited |

## koh vs ssh

koh and OpenSSH are different tools, and most of what ssh has that koh lacks — port/agent/X11
forwarding, ProxyJump, sftp, multiplexing, multi-user/PAM/ForceCommand — are **deliberate non-goals**
for a single-operator p2p shell (each is also an attack surface). On the axes that overlap, koh is
structurally ahead: **no listening TCP port** (no mass-scanning, no pre-auth-port RCE class, no
brute-force floods), **no TOFU window** (the id *is* the address, authenticated every connect), a
memory-safe `forbid(unsafe)` codebase two orders of magnitude smaller than sshd, and a single
**always-encrypted** identity key (safer than ssh's common unencrypted-key default). ssh's real,
non-shortcuttable edges: **post-quantum-default KEX** (koh inherits X25519-only from iroh — tracked,
not yet available), **FIDO2 hardware keys**, runtime **privilege separation/sandboxing**, and
decades of **audit + CVE-response maturity**.

| | OpenSSH | koh |
|---|---|---|
| Listening surface | TCP/22, Internet-scannable | **none** — node-id + allowlist |
| Host auth | known_hosts **TOFU** | dial-by-id, authenticated by construction, no TOFU |
| Post-quantum KEX | default (mlkem768x25519) | not yet (X25519, inherited from iroh) |
| Hardware keys (FIDO2) | yes | no (key always encrypted at rest) |
| Privsep / sandbox | yes (privsep + seccomp/pledge) | none (mitigated: no unsafe, no open port) |
| Memory safety | C | Rust, `forbid(unsafe)` |
| Forwarding / sftp / multiplex / multi-user | full suite | **omitted by design** |
| Maturity / audit | **decades, universal** | young, unaudited |

## Security at a glance

- **Authorization is a node-id allowlist — the sole gate.** At least one `--allow <id>` is required;
  there is no "accept any peer" mode and no passphrase/PAKE second factor (the node-id is
  cryptographically authenticated by the handshake, with no trust-on-first-use).
- **Every authorized peer is still untrusted on the data plane:** resize clamps before any vt100
  allocation, inflation/replay/reassembly/accumulation caps, bounded handshake + admission timeouts,
  and vt100 `catch_unwind` on both sides.
- **The identity key is always encrypted at rest** (Argon2id + AES-256-GCM, ≥12-char passphrase
  floor, 0600 / `O_NOFOLLOW`, zeroized); koh keeps every file it owns under `~/.config/koh`.

See [`SECURITY.md`](SECURITY.md) to report a vulnerability and [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)
for the full model. No external audit yet — calibrate trust accordingly.

## Non-goals

No wire compatibility with upstream mosh; no multiplexing (one session, one shell — use tmux for
windows/panes); no scrollback sync (only the visible screen, like mosh); no port/agent/X11
forwarding, sftp, or multi-user model. OSC-52 clipboard write is supported but **off by default**.

## Status & roadmap

Feature-complete against mosh's core (detachable sessions, terminal-reply synthesis, exit-status
propagation, the predictor, OSC-52). Hundreds of tests pass across the [tiers](docs/ARCHITECTURE.md#testing-tiers),
including end-to-end over real iroh and a full Android-emulator suite. This is the transport+terminal
core for a planned Bevy-based Android terminal; next up is two-device real-network acceptance and a
Bevy front-end reusing the `terminal` + `input` + `predict` + `transport_iroh` modules directly.

## Docs

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — the protocol, the modules, the design decisions, the testing tiers.
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — attackers, trust boundaries, defenses, non-goals.
- [`SECURITY.md`](SECURITY.md) — reporting a vulnerability.
- [`testing/android/`](testing/android/) — the opt-in Android-emulator suite.
- [`docs/research/`](docs/research/) — porting-research notes (mosh/iroh/vt100 internals).

## License

GPL-3.0-or-later (matching upstream mosh).
