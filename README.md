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
cargo install koh                                               # from crates.io
# or, latest from git:  cargo install --git https://github.com/gold-silver-copper/koh
# or, from a checkout:  cargo build --release
```

**Platforms:** Linux and macOS (x86_64 and aarch64), and Android via [Termux](https://termux.dev).
Windows is **not** supported (koh uses Unix PTYs + file-permission primitives) — use WSL2. koh is
**binary-first**: the library crate is published only so the in-tree tests can drive it, and its API
is **internal and unstable** — depend on the `koh` binary, not the crate API.

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

## Alternatives

koh's bet is a **combination no single alternative has**: mosh-style predictive echo + detach/reattach
+ p2p with no listening port + memory-safe Rust. The honest landscape (✅ built-in · ❌ no · ⚠️ partial):

| | **koh** | mosh | OpenSSH | Eternal Terminal | wush |
|---|---|---|---|---|---|
| Transport / reach | p2p QUIC, by node-id | UDP, over an SSH login | TCP `:22` | TCP `:2022`, over SSH | p2p WireGuard / DERP |
| No listening port | ✅ | ❌ (needs `sshd`) | ❌ | ❌ (needs `sshd`) | ✅ |
| Predictive local echo | ✅ | ✅ | ❌ | ❌ | ❌ |
| Reconnect / roam (survive IP change) | ✅ | ✅ | ❌ | ✅ | ⚠️ (WireGuard) |
| Persistent session (detach → reattach) | ✅ | ❌ | ❌ (use tmux) | ✅ | ❌ |
| Scrollback | ❌ (screen-sync only) | ❌ | ✅ | ✅ | ✅ |
| File transfer | ❌ | ❌ | ✅ (scp/sftp) | ❌ | ✅ (`wush cp`) |
| Port forwarding | ❌ | ❌ | ✅ | ✅ | ❌ |
| Auth | node-id allowlist, **no TOFU** | via SSH | keys / 2FA / FIDO2, TOFU host | via SSH | shared overlay key |
| Multi-user / accounts | ❌ (single-operator) | ✅ (SSH) | ✅ | ✅ (SSH) | ❌ |
| Language | Rust, `forbid(unsafe)` | C++ | C | C++ | Go |
| Maturity | new (2026) | mature, ubiquitous | universal | established | new (2024) |

- **[mosh](https://mosh.org)** — the predictive-echo + roaming ancestor koh descends from. koh adds
  detach/reattach, forward-secret per-session crypto, and p2p with no SSH dependency. *Still pick mosh*
  for a battle-tested tool that's packaged everywhere and rides your existing SSH accounts/2FA.
- **OpenSSH** — the universal everything-tool: forwarding, sftp, agent, jump hosts, multi-user. koh
  isn't a replacement — it's a focused interactive shell that's safer by construction (no port, no
  TOFU, Rust). ssh's edges koh lacks: post-quantum-default KEX, FIDO2 hardware keys, privilege
  separation, and decades of audit. *Still pick ssh* for file transfer, tunnels, accounts, or scripting.
- **[Eternal Terminal](https://eternalterminal.dev)** — reliable auto-reconnect + native scrollback +
  port-forwarding over an SSH-bootstrapped TCP link. koh adds predictive echo and p2p (no port, no
  SSH) but lacks ET's scrollback. *Still pick ET* if you live in scrollback, must cross a strict
  TCP-only firewall, or want SSH-native auth.
- **[wush](https://github.com/coder/wush)** — koh's closest modern-p2p cousin (WireGuard/DERP) and the
  file-transfer king (`wush cp`). koh adds the mosh-feel (predictive echo, detach/reattach) and drops
  the Tailscale/WireGuard dependency, but has **no file transfer yet**. *Still pick wush* for
  one-command p2p file transfer.

> Also at the edges: tmux/zellij (multiplexing), sshx/upterm (terminal sharing), Tailscale SSH /
> Teleport (managed access). koh's lane is the **mobile-first, predictive, p2p interactive shell** —
> and its biggest gaps vs the field are **file transfer** and **scrollback**.

## Why koh doesn't ride on SSH (the way mosh does)

mosh isn't a standalone protocol — it **bootstraps over an SSH login**. `mosh user@host` runs `ssh`
first, which authenticates you, drops you into your **account**, and launches `mosh-server`; mosh then
takes over the interactive session over UDP. So mosh inherits SSH's auth, accounts, host keys,
bastions, agent, and PAM/2FA **for free** — it only had to solve the responsive-roaming-session piece.

koh deliberately doesn't, because every koh property depends on *not* needing SSH:

- **No listening port.** Riding on SSH means a reachable `sshd` — an open TCP port plus its whole
  codebase in the trust path. koh is reachable only by a non-enumerable node-id through relays /
  hole-punching, *including a machine with no open ports at all* (your phone → your NAT'd PC). That's
  the whole p2p/mobile premise.
- **No TOFU, no second protocol, forward secrecy.** koh's node-id *is* the identity, authenticated by
  the QUIC/TLS handshake on every connect — no `known_hosts` first-use window, and no static session
  key piggybacked over a second protocol (mosh's `MOSH_KEY`). koh's own channel is already stronger, so
  there's nothing to gain by bootstrapping over SSH.

**The honest trade:** by solving auth itself — cryptographically, via the node-id allowlist — koh gives
up what SSH handed mosh for free: **user accounts / multi-user, SSH's auth factors (passwords, 2FA,
FIDO2, PAM) and policy (`ForceCommand`, `authorized_keys` options), and the universal `sshd` install
base.** That is why koh is a *single-operator tool for machines you own*, not an ssh replacement. (A
future opt-in "koh over an existing SSH connection" mode could inherit SSH's auth while keeping koh's
predictive-echo + detach/reattach session — but it would re-add the open port and a second protocol, so
it's deliberately out of scope today.)

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
