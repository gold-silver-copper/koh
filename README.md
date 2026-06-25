# koh — mosh, rewritten in Rust over iroh

`koh` is a from-scratch Rust reimplementation of [mosh](https://mosh.org)
(the mobile shell) whose transport is **[iroh](https://iroh.computer) peer-to-peer QUIC**
instead of mosh's UDP/OCB. It gives you mosh's signature feel — instant local echo on laggy
links, survival across suspend/resume and IP changes, no head-of-line blocking — while iroh
handles encryption, NAT traversal, relay fallback, connection migration, and RTT.

> The name is from *Avatar: The Last Airbender* (a nod to iroh): **Koh the Face Stealer** takes
> you the instant you show any *past* expression — survival means showing only your *current*
> face. That is this protocol exactly: only the **latest** screen state is authoritative; every
> superseded state is collapsed and discarded.

It is the transport+terminal core for an eventual Bevy-based Android terminal for vibe-coding
over your phone to your main PC. This repo is that core: a single binary, `koh`, with three
subcommands — `koh serve` (host a shell), `koh connect <id>` (attach to one), and `koh id`
(print your id) — that give you a real remote shell by endpoint id.

> Status: feature-complete against mosh's core. The protocol core, terminal model, PTY host,
> predictor, and iroh transport are implemented and tested, plus the defining mosh features:
> **detachable/reattachable sessions** (close the lid, reconnect, your shell is right where you
> left it), **terminal-reply synthesis** (DSR/DA/DECRQM, so vim/htop/fzf behave), and
> **remote-shell exit-status propagation**. Client terminal I/O runs on
> [termina](https://github.com/helix-editor/termina) with synchronized output (no crossterm).
> A few hundred tests pass across the tiers below — unit and property tests, a network-chaos simulator, an in-process
> client↔server scenario that converges at 50% packet loss, a reattach acceptance test, an
> auto-reconnect-after-forced-drop test, **end-to-end tests over a real iroh connection** (both
> the full loop in one process and the real `koh` binary driven through an allocated
> PTY), and a suite of upstream **mosh regression tests** ported to koh's architecture
> (terminal-emulation round-trips, the unicode-prediction bug, pty-deadlock/repeat/window-resize,
> network-no-diff). See [Testing tiers](#testing-tiers).

## The one idea

koh is **not a tunnel**. It does not ship a byte stream. It is a *state-synchronization*
system whose payload happens to be a terminal. Each side holds an authoritative object and the
protocol's only job is to bring the peer to the **latest** version of it — intermediate states
are collapsed and discarded. If the screen changed 100 times in 40ms, only the final state is
sent. This is the source of every property users love: instant re-sync after a drop (never
replay a backlog), responsiveness on lossy links, and no head-of-line blocking.

## Architecture

A single crate, organized into small, independently-tested modules:

```
src/
├── lib.rs           crate root: module declarations + the architecture overview
├── main.rs          the `koh` binary: `serve` / `connect` / `id` subcommand dispatch
├── wire.rs          SSP instruction envelope, postcard codec, fragmenter/reassembler
├── ssp/             SyncState trait + generic Transport<Local,Remote> + send scheduler
│                      + a deterministic lossy/reordering chaos sim harness (testkit)
├── terminal/        TerminalScreen state (vt100-backed) + ServerTerminal live emulator
├── input.rs         UserInput state: keystrokes + resize as an append-only synced log
├── predict.rs       local-echo prediction engine (overlays, epochs, adaptive engage)
├── transport_iroh/  iroh endpoint setup, persistent identity, datagram channel, RTT, auth
├── pty.rs           PTY allocation, shell spawn, SIGWINCH, child reaping
├── server/          PTY + emulator + Transport<Screen,Input> over iroh + `serve`
├── client/          input + Transport<Input,Screen> + predictor + termina render + `connect`
└── sim.rs           in-process integration/chaos driver (used by tests + the chaos example)
tests/               real-iroh e2e, reattach, auto-reconnect, PTY-binary, ported mosh regressions
examples/chaos.rs    manual `cargo run --example chaos -- chaos --loss 0.5` driver
```

Dependency direction is strict: `wire ← ssp ← {terminal, input}`, with `predict` over
`{terminal, input}`, `transport_iroh` over `wire`, and `server`/`client` (+ the `main` binary) on
top. Only `transport_iroh`, `server`, and `client` touch iroh — the entire protocol (`ssp`,
`terminal`, `input`, `predict`, `wire`) is transport-agnostic and tested with no network at all.

### The two synchronized states

- **`TerminalScreen`** (server → client) wraps a `vt100` screen grid. Its diff is the
  `vt100` `state_diff` escape-sequence patch, plus a side-band `resize` (full repaint on size
  change, since vt100 does not reflow) and the server's `echo_ack`. `vt100::Parser` is not
  `Clone`, so the state holds an owned `vt100::Screen` snapshot; the client reconstructs a
  throwaway parser to replay each diff.
- **`UserInput`** (client → server) is the keystroke + resize stream, stored per-byte (so an
  acked prefix is a clean prefix) and coalesced into compact `Keys` blobs on the wire.

### The Transport

One `Transport<Local, Remote>` per peer — a faithful port of mosh's `TransportSender` +
receive path, restructured as a **pure, clock-injected state machine** (no sockets, no async).
It keeps the `sent_states`/`received_states` collapse logic, the `tick()` send scheduler with
mosh's exact timers (`SEND_INTERVAL_MIN/MAX`, `ACK_INTERVAL`, `ACK_DELAY`, `SEND_MINDELAY`,
`ACTIVE_RETRY_TIMEOUT`), the seq/ack/throwaway envelope, the prospective-resend optimization,
and the shutdown handshake. Because it is pure, the whole protocol is deterministically
testable under simulated loss/latency/reordering/duplication.

### Headless drivers (the protocol is I/O-free; the shells are thin)

The client session loop is split the same way the `Transport` is: a synchronous, I/O-free
**`ClientSession`** owns the transport, predictor, and escape/render state and exposes pure step
methods — `on_input` (the `Ctrl-^`-prefix machine + prediction seeding), `on_datagram`,
`on_resize`, and `on_tick` (which returns the datagrams to send, the next wait, the link-down
banner, and the remote exit code) — none of which touch tokio, iroh, or a real terminal. The
screen is *derived* from the transport, so the renderer draws through borrows with no extra
clone. `run_client` is then a thin shell: the `tokio::select!` (kept `biased` for input
priority), the channels/sleeps, and `term.render()`, delegating every protocol decision to the
session. This makes the whole client deterministically unit-testable and lets a future front-end
(the planned Bevy terminal) drive the same core without the I/O scaffolding.

On the server side, **PTY writes are non-blocking**: a dedicated `koh-pty-writer` thread owns
the blocking write handle and drains a bounded channel, so forwarding a keystroke (or a synthesized
DSR/DA reply) only enqueues and never blocks a tokio worker on a slow child. Both producers share
one sender and enqueue under the session lock, so byte order is preserved (a query reply can't
overtake the keystroke that triggered it).

## Two design decisions called out by the spec

### Fragmentation (how oversized state crosses the wire)

**koh ships the SSP over QUIC *unreliable datagrams*, never a reliable stream for the steady
flow** — a reliable ordered stream would reintroduce head-of-line blocking and defeat the
"drop superseded state" property. We use mosh's own approach **(option a): a fragmenter**.
A serialized instruction larger than the path MTU is split into datagram-sized `Fragment`s
that share an id; the reassembler keeps only the highest id it has seen, so a newer
instruction's fragments supersede and discard any stale partial — the drop-superseded property
extends down to the framing layer. Identical retransmits reuse fragment ids so a partially
received instruction can complete across retransmissions. The datagram budget is taken from
`Connection::max_datagram_size()` (re-queried, since it tracks the path MTU).

Every state (even a full repaint) goes through the fragmenter over unreliable datagrams — there
is no reliable-stream fallback, since a reliable ordered stream would reintroduce the
head-of-line blocking the whole design avoids. The chaos tests exercise the fragmenter down to
a 30-byte MTU at 30% loss.

### Authorization (who gets a shell)

On iroh, identity is the endpoint's public key. koh deliberately does **not** copy
iroh-ssh's "anyone with the endpoint id gets a shell" model. The server:

- uses a **persistent secret key** (so its endpoint id is stable across restarts), and
- **allowlists client endpoint ids** — a connection is served only if the client's id is on
  the `--allow` list. `--allow-any` exists for local testing and prints a loud warning.

QUIC/iroh already authenticates both ends by public key and encrypts everything; the allowlist
is the authorization layer on top.

#### Per-peer authorization (`--allow-file`)

A bare `--allow <id>` grants a full interactive shell. To vary policy per peer — sshd's
`authorized_keys` options / `ForceCommand` — pass `--allow-file <path>`, one entry per line:

```text
# observer: can watch the live shell but cannot type or resize it
871b…aa  restrict
# kiosk: always lands in a fixed command instead of a login shell
a2d4…bf  command="tmux attach -t main"
# both: a read-only view of a fixed command
3f9c…01  restrict command="watch -n1 uptime"
```

- **`restrict`** is a *real* boundary: the peer's keystrokes and resizes are dropped before they
  reach the PTY (enforced in the data path, not just advertised). `--read-only` applies this to
  **every** authorized client.
- **`command="…"`** runs via the login shell's `-c`, exactly like sshd's `ForceCommand`. Because
  koh is a **single-uid** tool (the shell runs as whoever launched `koh serve`), a forced command
  is a *convenience / soft restriction*, **not a jail**: a command that can spawn a subshell (an
  editor's `:!sh`, a pager, …) escapes it. For anything resembling confinement, pair it with
  `restrict` and a command that can't shell out.

`#` comments and blank lines are ignored; a malformed id, unknown option, or duplicate id fails at
startup rather than silently mis-authorizing. Each accepted connection's resolved policy is logged
under the `koh::auth` target.

#### Single factor by design (no passphrase / second factor)

koh authorizes on the node-id allowlist alone. There is **no over-the-wire passphrase / PAKE second
factor**: the peer's node-id is already cryptographically authenticated by the iroh QUIC/TLS 1.3
handshake, and the residual "leaked client key" risk is handled where it belongs — the identity key
is **always encrypted at rest** (see below), so a stolen key file is useless without its passphrase.
Removing the bespoke PAKE also removes koh's largest piece of un-audited custom crypto. The trade-off
is honest: the node-id is now the *sole* authenticator of which machine you reached, so **verify a
server's node-id out-of-band** before trusting a session — there is no second factor to catch a
wrong/typo'd id.

#### Hardening against a hostile or compromised peer

koh treats every value on the wire as untrusted and bounds what a malicious peer can do:

- **Resize is clamped** to `[2, 1000]` rows/cols before it reaches the terminal emulator, on both
  ends. An unbounded resize would otherwise allocate `rows × cols` cells eagerly (a `65000×65000`
  ≈135 GB OOM bomb — cross-tenant on the server, which holds every peer's session), and a degenerate
  `0`/`1` dimension would panic the emulator. One crafted datagram can no longer take a session — or
  the whole server — down.
- **Window title / icon / clipboard are capped on the client too** (256 chars / 16 KiB), not only in
  the trusted server emulator — the client never trusts the wire's framing.
- **Remote clipboard writes (OSC-52) are opt-in.** By default a server **cannot** set your local
  system clipboard (it could otherwise silently swap a copied command for `curl evil | sh`). Enable
  per session with `--clipboard`; even then the payload must be strict base64 within the cap.
- **The secret identity key is written `0600`** (owner-only) into a `0700` state dir — it *is* the
  node's identity, so a world-readable key would be a local-impersonation risk. koh warns if it finds
  an existing key with looser permissions.
- **Connections and sessions are bounded** (`--max-connections`, `--max-sessions`, default 64 each):
  excess dials are refused cheaply before the crypto handshake, and a flood of distinct keys can't
  spawn unbounded shells under `--allow-any`.

## Build

```sh
cargo build --release          # builds the single `koh` binary (target/release/koh)
cargo test                     # unit, property, chaos sim, real-iroh e2e, reattach, auto-reconnect, PTY binary, ported mosh regressions
```

Pinned toolchain-adjacent versions live in the root `Cargo.toml`: `iroh =1.0.0` (which brings
its own QUIC backend, `noq`, a quinn fork — we never depend on quinn directly), `vt100 0.16`,
`portable-pty 0.9`, `termina 0.3` (client terminal I/O), `postcard 1.1`.

## Run a session by endpoint id

On the **server** (your PC). First find out the client's id, then authorize it:

```sh
# on the client machine, print its stable endpoint id:
koh id
#   3f9c…(64 hex chars)

# on the server, allow that client and start:
koh serve --allow 3f9c…
# ┌─ koh server ready ──────────────────────────────────────
# │ endpoint id : 871b…
# │ connect     : koh connect 871b…
# └───────────────────────────────────────────────────────────
```

On launch the server also prints the endpoint id as a scannable terminal QR code — point a
phone camera at it instead of copying 64 hex chars. It's rendered for a dark-background terminal.

On the **client** (your phone/laptop), connect by the server's endpoint id:

```sh
koh connect 871b…
# connected. (Ctrl-^ then . to disconnect)
```

The server's identity persists in `~/…/koh/server.key` (override with `--key-file`); the
client's in `~/…/koh/client.key`. Prediction policy is `--predict adaptive|always|never`
(default adaptive: it engages only when the link is slow enough to benefit). Set
`KOH_LOG=/tmp/koh.log` to capture client logs without disturbing the TUI.

### Environment variables & logging

All of koh's knobs as environment variables (most have a CLI-flag equivalent):

| Variable | Applies to | Effect | Flag equivalent |
|---|---|---|---|
| `RUST_LOG` | serve, connect | Log verbosity/filter (`tracing` `EnvFilter`), e.g. `koh=debug` or `koh::server=info`. Server logs to **stderr**; client logs to `$KOH_LOG`. | — |
| `KOH_LOG` | connect | File the client writes logs to (created `0600`), so logging doesn't disturb the TUI. | — |
| `KOH_KEY_PASSPHRASE` | serve, connect, key | Passphrase to decrypt the (always-encrypted) identity key. Lets an unattended `koh serve`/`koh connect` open the key without a TTY prompt. | — |
| `KOH_KEY_NEW_PASSPHRASE` | serve, connect, key | Passphrase used when **creating** a key on first run, and the new passphrase for `koh key passwd`; for CI/automation instead of the confirmed prompt. Must be non-empty. | — |
| `KOH_STATE_DIR` | serve, connect | Base directory for the identity key files (the server's error message points here when the default isn't writable). | `--key-file` (per file) |
| `KOH_DNS` | serve, connect | Override the discovery DNS resolver (`IP` or `IP:PORT`); needed on some Android/Termux setups. | — |

> Debugging a stuck session? Start the client with `RUST_LOG=koh=debug KOH_LOG=/tmp/koh.log` and the
> server with `RUST_LOG=koh=debug` (it logs to stderr). At `debug` the client also reports link RTT,
> so you can tell a slow link from a slow server.

### The identity key (always encrypted at rest)

The identity key *is* the node — anyone who can read `~/…/koh/{server,client}.key` owns the identity.
koh **always** stores it passphrase-encrypted (`koh-key-v1`: **Argon2id + AES-256-GCM**, modeled on
OpenSSH's `openssh-key-v1`); there is **no plaintext format**. So a stolen/backed-up key file is
useless without the passphrase — file permissions are no longer the only thing protecting it.

On first run, `koh serve`/`koh connect` generate the key and prompt for a passphrase to encrypt it
(or read `$KOH_KEY_NEW_PASSPHRASE` when there's no TTY). Thereafter every command that loads the key
prompts for it, or reads `$KOH_KEY_PASSPHRASE` for unattended use:

```sh
koh key passwd               # change the passphrase (like ssh-keygen -p); prompts with confirmation
koh key info                 # show endpoint id (prompts for the passphrase)
koh key passwd --key-file ~/.config/koh/server.key   # operate on the server key
```

The key material is never changed, so the endpoint id is preserved across a passphrase change. For
an unattended `koh serve`, set `KOH_KEY_PASSPHRASE`. **Caveat:** at-rest encryption only protects a
stolen key if the passphrase is *not* stored next to it — a daemon with `KOH_KEY_PASSPHRASE` in the
same unit file on the same disk gains little. (This is at-rest custody only, not hardware/agent-backed
— see the roadmap.)

By default the bare endpoint id is dialed via n0's public relay + DNS discovery. For a LAN or
self-hosted setup you can skip that:

```sh
# same LAN / loopback, no relay: server prints its port, client dials it directly
koh serve --local --allow 3f9c…             # connect: koh connect 871b… --direct <ip>:<port>
koh connect 871b… --direct 192.168.1.5:41xxx

# self-hosted relay (e.g. your own iroh-relay), both ends point at it
koh serve --relay-url https://relay.example:3340 --allow 3f9c…
koh connect 871b… --relay-url https://relay.example:3340
```

### Android / Termux

A bare-id connection works in Termux out of the box. iroh constructs a DNS resolver for every
endpoint, and its default reads the host's system DNS through Android's app JNI context — which a
plain CLI (no Android app) doesn't have, so the read used to **panic**
(`ndk-context: android context was not initialized`). koh now pins an explicit public
nameserver (Google `8.8.8.8:53`) on Android, sidestepping that read entirely. Set
`KOH_DNS=<ip>` or `KOH_DNS=<ip:port>` (e.g. `KOH_DNS=1.1.1.1`) on **any** platform to point
iroh's discovery at a different resolver — useful if `8.8.8.8` is blocked on your network. (On
desktop, leaving it unset keeps your system DNS, so split-horizon / corporate resolvers still
work.)

Sessions are **detachable**, like mosh: the server keeps your shell (and its live screen)
running after a disconnect, keyed by your client endpoint id, so reconnecting from the same
client drops you back exactly where you left off — no `tmux` required for survival across
suspend/resume or IP changes. A detached session is reaped after `--session-ttl-secs` (default
24h) or immediately when its shell exits. koh still does no multiplexing (one session, one
shell, exactly like mosh) — use `tmux` if you want windows/panes.

The reconnect is **automatic and in-process**: the client doesn't exit when the link drops. A
brief outage (e.g. a phone screen-off — Android freezes the process, so QUIC keepalives stop) is
ridden out on the same connection thanks to a 5-minute connection idle timeout. A longer outage
times the connection out; the client then transparently re-dials and reattaches to the same
server session, holding the last screen under a `reconnecting…` banner in the meantime (`Ctrl-^ .`
still quits). You stay in your shell instead of being dropped back to the local prompt. On Android
especially, run `termux-wake-lock` (and set Termux to *Unrestricted* battery) so the OS doesn't
freeze or kill the process during a long screen-off.

> **Fast wake-up after a long screen-off.** A system suspend pauses the *monotonic* clock that
> iroh's idle timer runs on, so after a long deep-sleep iroh can't tell the connection went stale
> and would otherwise hold it for up to the full ~5 minutes before giving up. The client guards
> against this with a **wall-clock freeze detector**: if real time jumps more than 20s between two
> (≤50ms-cadence) loop iterations, it concludes the process was suspended, drops the (almost
> certainly dead) connection, and re-dials immediately — turning a multi-minute wake-up hang into a
> ~1–2s reattach. A sub-20s glance still rides out silently on the existing connection.

> **`--direct` caveat:** transparent re-dial targets the *same* address it first dialed, so a
> `--direct <ip:port>` client can't reconnect if the server restarts on a new ephemeral **port**.
> The relay/discovery path (a bare endpoint id) re-dials by node id and reconnects across address
> changes — use it (or a fixed port) when you need reconnection to survive a server restart.

## The predictor

The client guesses what each keystroke does to the screen and shows it immediately (underlined
on high-RTT links), then confirms or corrects when the authoritative server frame arrives.
Confirmation is driven by the server's **echo-ack** (a 50ms-debounced "your input up to frame
N is now on screen"), not the raw network ack. Password prompts get no predicted echo —
suppression is *emergent*: non-echoed input fails validation, kills its epoch, and keeps
subsequent predictions hidden, with no explicit password heuristic. Engagement is adaptive by
SRTT with hysteresis (show > 30ms, flag/underline > 80ms).

The port faithfully implements epoch-gated confirmation, adaptive engagement, flagging, glitch
escalation, and no-echo suppression. It predicts ASCII printables (with insert-mode row shift),
backspace, CR/LF, the left/right arrow keys (CSI **and** SS3/application-cursor form), and whole
UTF-8 graphemes including double-width CJK/emoji (cursor advances by two cells). Control/escape
sequences it doesn't model open a fresh epoch but make no concrete guess (they fall back to the
server's real echo). A wrong or unconfirmed guess is always reconciled away — it never corrupts
the display.

## Testing tiers

You never need a second *machine* to develop koh — you need a second *process* and
occasionally a second *container*. "Real relay" becomes "local relay container"; "TTY" becomes
"allocated PTY". The verification is layered cheapest-first; everything but Tier 3 is headless.

### Tier 0 — pure logic, no infra (`cargo test`)

The SSP, diff/apply, and predictor are network- and TTY-free, so they're tested deterministically:

- **State round-trip** — `apply(diff(base→target))` over `base` equals `target`, for screens
  (incl. wide chars / emoji / combining marks) and input.
- **Transport under chaos** (`ssp::testkit`) — two transports through a seeded
  lossy/latent/reordering/duplicating link; asserts convergence *and* that the newest applied
  state number never regresses (the no-head-of-line-blocking guard).
- **Terminal / predictor / PTY / fragmenter** — diff+resize, predict→confirm→clear,
  predict→no-echo→suppress, real-shell streaming, fragment supersede/reassemble.
- **Whole-stack chaos** (`xtask`) — input + screen + transport + collapse + echo-ack over the
  simulated link: `cargo run --example chaos -- chaos --loss 0.5` (or `cargo test --test integration`).

### Tier 1 — two endpoints + a PTY on localhost, over *real* iroh (`cargo test`)

The big unlock, with **zero infrastructure**: a second host is just a second endpoint, and a
TTY is just an allocated PTY. Both are real and hermetic.

- **`transport_iroh` module tests** — two real iroh endpoints connect over loopback (relay-less,
  `bind_endpoint_local`) and exchange datagrams: upgrades the iroh layer from "compiles against
  the 1.0 API" to "actually established a connection."
- **`tests/e2e_loopback.rs`** — the *entire* loop in one process: scripted
  keystroke → client → iroh datagram → server → PTY-hosted `sh` → vt100 → iroh → client render
  (through a `ClientTerminal` mock backend). Asserts the typed command's output round-trips.
- **`tests/e2e_pty_binary.rs`** — the **real `koh` binary** (`koh connect …`) attached
  to an allocated PTY (so `isatty()` is true and raw-mode + termina run for real), driven by
  scripted keystrokes with rendered frames read back from the master, connected with `--direct`
  to an in-process loopback server.
- **`tests/reattach.rs`** — the detachable-session acceptance test: type a marker,
  disconnect, reconnect from the *same* client endpoint, assert the session re-syncs to the
  persisted screen (the shell kept running while detached).
- **`tests/e2e_reconnect.rs`** — the **auto-reconnect** regression test: mid-session,
  the server force-closes the connection (what a screen-off idle-timeout does) while keeping the
  shell; asserts the client transparently re-dials, reattaches to the *same* shell (the first
  command's output is still on screen), and keeps working — instead of exiting to the prompt.
- **`tests/exit_status.rs`** — a loopback session where `sh` runs `exit 42`;
  asserts the client observes exit code `42` on the shutdown frame (so the binary exits with it).

The seam that makes this cheap: terminal I/O is abstracted behind `ClientTerminal`, so the same
session loop runs against the real termina path (binary) or a captured-cells mock (fast test).

### Tier 2 — Android emulator: runtime, network realism, resilience (`testing/android/`)

The layer a single in-process test can't reach: the **real `koh` binary on a real Android OS**,
driven over `adb`. See [`testing/android/`](testing/android/) — opt-in (`KOH_ANDROID_EMULATOR=1`),
never part of `cargo test`. A **smoke** suite proves the Android iroh/DNS path binds without the
`ndk-context` panic (a runtime-only bug cross-compilation can't catch); a **stress** suite hammers
koh under load, churn, and adverse conditions — connection churn, concurrent sessions, an auth
flood, throughput + memory-longevity (leak checks), signal handling, a short screen-off freeze
(rides out on the same connection) and a long one (the wall-clock freeze detector forces a fast
proactive reconnect), detachable-session reattach continuity, `tc netem` loss/jitter/reorder
*beneath* real QUIC, a
total-outage roaming analogue, and a bare-id connection over the public relay (real DNS resolution).
This absorbed the old Docker `tier2/` scaffolding; a literal multi-network roam (the client's IP
changing) and NAT hole-punching still need two hosts — see Tier 3.

### Tier 3 — real devices (manual)

A small final human acceptance pass, not for an agent: paste the endpoint id on an actual
Android phone, connect to an actual Mac over the public relay, type on a laggy cell link, and
feel the predictions. The last 1% sign-off after Tiers 0–2 are green. The headless tiers prove
correctness; only a real two-device run over a real radio proves *feel* and migration, so this
step stays manual. Concrete checklist (each maps to a parity feature):

1. **Predictor feel** — on a cell link, type a long command; characters appear instantly
   (underlined while RTT is high), then settle as the server confirms.
2. **Suspend/resume + roaming** — lock the phone or switch Wi-Fi↔cellular mid-session; the
   client shows "link down — resuming…", then re-syncs to the *current* screen (no backlog)
   once QUIC migrates.
3. **Detach/reattach** — fully quit the client (Ctrl-^ then `.`) with a long-running program
   on screen, reconnect later; the shell is right where you left it (the server kept it alive).
4. **Interactive apps** — run `vim`, `htop`, `fzf`; they render and respond (terminal-reply
   synthesis answers their DSR/DA/DECRQM probes).
5. **Exit status** — `exit 42` in the remote shell; the client process exits with code 42
   (`echo $?` locally).
6. **Perf** — under packet loss, a burst of output never stalls the current frame, and
   keystroke→echo latency tracks RTT, not output volume (the state-collapse guarantee).

## Acceptance criteria (mosh feel)

| Property | How koh delivers it |
|---|---|
| Keystrokes appear instantly on high-RTT links | predictor (adaptive, underlined, then confirmed) |
| Survives suspend/resume + IP change, re-syncs to current screen | QUIC connection migration + SSP re-sync to latest (no backlog) |
| A burst of superseded output never delays the current screen | datagram transport + state collapse; proven by the chaos monotonicity guard |
| Password prompts show no predicted echo | emergent no-echo suppression in the predictor |
| Reconnect lands you where the screen is *now* | SSP always diffs toward the latest state |
| Detach and reattach later, shell still running | server-side detachable sessions keyed by client id (reattach test) |
| Interactive apps (vim/htop/fzf) that probe the terminal work | server synthesizes DSR/DA/DECRQM replies |
| Client exits with the remote shell's status | exit code rides the shutdown frame (exit_status test) |

## Non-goals / divergences

- **No wire compatibility with upstream mosh** (impossible over iroh; we use postcard, not
  protobuf, and drop OCB/heartbeats/chaff).
- **No multiplexing** — one session, one shell; use tmux.
- iroh-ssh was a reference for the iroh bootstrap only, not a base to extend.
- **No scrollback sync** — like mosh, only the visible screen is synchronized (use a pager/tmux).
- Title/bell propagate and terminal *replies* (DSR/DA/DECRQM) are synthesized server-side, so
  interactive apps that probe the terminal (vim/htop/fzf) work. **OSC-52 clipboard** forwarding to
  the local clipboard is supported but **off by default** (opt in with `--clipboard`) — a remote
  server shouldn't silently write your system clipboard.

## Roadmap

This core is the foundation for a 100%-Rust mobile (Android) terminal — likely Bevy-based —
that vibe-codes over koh to your main PC. With mosh's core behaviors now in place (detachable
sessions, terminal-reply synthesis, exit-status propagation, the predictor), the natural next
steps are OSC-52 clipboard forwarding, two-device real-network/perf acceptance over the public
relay (Tier 3), and a Bevy front-end reusing the `terminal` + `input` + `predict` +
`transport_iroh` modules directly.

## License

GPL-3.0-or-later (matching upstream mosh).
