# koh architecture

How koh is built. The [README](../README.md) covers what it does and how to use it; this is the
internals. Pair it with the [threat model](THREAT_MODEL.md) and the porting-research notes under
[`research/`](research/).

## The one idea

koh is **not a tunnel**. It does not ship a byte stream. It is a *state-synchronization* system
whose payload happens to be a terminal. Each side holds an authoritative object and the protocol's
only job is to bring the peer to the **latest** version of it — intermediate states are collapsed
and discarded. If the screen changed 100 times in 40 ms, only the final state is sent. This is the
source of every property users love: instant re-sync after a drop (never replay a backlog),
responsiveness on lossy links, and no head-of-line blocking. It is a faithful port of mosh's SSP
(State Synchronization Protocol), retargeted from UDP/OCB onto iroh's QUIC.

## Module layout

A single crate, organized into small, independently-tested modules:

```
src/
├── lib.rs           crate root: module declarations + the architecture overview
├── main.rs          the `koh` binary: serve / connect / id / key subcommand dispatch
├── wire.rs          SSP instruction envelope, postcard codec, fragmenter/reassembler
├── ssp/             SyncState trait + generic Transport<Local,Remote> + send scheduler
│                      + a deterministic lossy/reordering chaos sim harness (testkit)
├── terminal/        TerminalScreen state (vt100-backed) + ServerTerminal live emulator
├── input.rs         UserInput state: keystrokes + resize as an append-only synced log
├── predict.rs       local-echo prediction engine (overlays, epochs, adaptive engage)
├── transport_iroh/  iroh endpoint setup, encrypted identity, datagram channel, RTT, admission
├── pty.rs           PTY allocation, shell spawn, SIGWINCH, child reaping
├── server/          PTY + emulator + Transport<Screen,Input> over iroh + `serve`
├── client/          input + Transport<Input,Screen> + predictor + termina render + `connect`
├── keycmd.rs        `koh key` — change the identity key's passphrase
└── sim.rs           in-process integration/chaos driver (used by tests + the chaos example)
tests/               real-iroh e2e, reattach, auto-reconnect, PTY-binary, ported mosh regressions
examples/chaos.rs    manual `cargo run --example chaos -- chaos --loss 0.5` driver
```

Dependency direction is strict and CI-enforced: `wire ← ssp ← {terminal, input}`, with `predict`
over `{terminal, input}`, `transport_iroh` over `wire`, and `server`/`client` (+ the `main` binary)
on top. Only `transport_iroh`, `server`, and `client` touch iroh — the entire protocol (`ssp`,
`terminal`, `input`, `predict`, `wire`) is transport-agnostic and tested with no network at all.
`predict` imports nothing from `crate::`, so it is a standalone, reusable terminal-prediction
library.

## The two synchronized states

- **`TerminalScreen`** (server → client) wraps a `vt100` screen grid. Its diff is the `vt100`
  `state_diff` escape-sequence patch, plus a side-band `resize` (full repaint on size change, since
  vt100 does not reflow) and the server's `echo_ack`. `vt100::Parser` is not `Clone`, so the state
  holds an owned `vt100::Screen` snapshot; the client reconstructs a throwaway parser to replay each
  diff.
- **`UserInput`** (client → server) is the keystroke + resize stream, stored per-byte (so an acked
  prefix is a clean prefix) and coalesced into compact `Keys` blobs on the wire.

## The Transport

One `Transport<Local, Remote>` per peer — a faithful port of mosh's `TransportSender` + receive
path, restructured as a **pure, clock-injected state machine** (no sockets, no async). It keeps the
`sent_states`/`received_states` collapse logic, the `tick()` send scheduler with mosh's exact timers
(`SEND_INTERVAL_MIN/MAX`, `ACK_INTERVAL`, `ACK_DELAY`, `SEND_MINDELAY`, `ACTIVE_RETRY_TIMEOUT`), the
seq/ack/throwaway envelope, the prospective-resend optimization, and the shutdown handshake. Because
it is pure, the whole protocol is deterministically testable under simulated
loss/latency/reordering/duplication.

## Headless drivers (the protocol is I/O-free; the shells are thin)

The client session loop is split the same way the `Transport` is: a synchronous, I/O-free
**`ClientSession`** owns the transport, predictor, and escape/render state and exposes pure step
methods — `on_input` (the `Ctrl-^`-prefix machine + prediction seeding), `on_datagram`, `on_resize`,
and `on_tick` (which returns the datagrams to send, the next wait, the link-down banner, and the
remote exit code) — none of which touch tokio, iroh, or a real terminal. The screen is *derived*
from the transport, so the renderer draws through borrows with no extra clone. `run_client` is then
a thin shell: the `tokio::select!` (kept `biased` for input priority), the channels/sleeps, and
`term.render()`, delegating every protocol decision to the session. This makes the whole client
deterministically unit-testable and lets a future front-end (the planned Bevy terminal) drive the
same core without the I/O scaffolding.

On the server side, **PTY writes are non-blocking**: a dedicated `koh-pty-writer` thread owns the
blocking write handle and drains a bounded channel, so forwarding a keystroke (or a synthesized
DSR/DA reply) only enqueues and never blocks a tokio worker on a slow child. Both producers share
one sender and enqueue under the session lock, so byte order is preserved (a query reply can't
overtake the keystroke that triggered it).

## Fragmentation (how oversized state crosses the wire)

**koh ships the SSP over QUIC *unreliable datagrams*, never a reliable stream for the steady flow**
— a reliable ordered stream would reintroduce head-of-line blocking and defeat the "drop superseded
state" property. We use mosh's own approach: a **fragmenter**. A serialized instruction larger than
the path MTU is split into datagram-sized `Fragment`s that share an id; the reassembler keeps only
the highest id it has seen, so a newer instruction's fragments supersede and discard any stale
partial — the drop-superseded property extends down to the framing layer. Identical retransmits
reuse fragment ids so a partially received instruction can complete across retransmissions. The
datagram budget is taken from `Connection::max_datagram_size()` (re-queried, since it tracks the
path MTU). Even a full repaint goes through the fragmenter; there is no reliable-stream fallback.

## The predictor

The client guesses what each keystroke does to the screen and shows it immediately (underlined on
high-RTT links), then confirms or corrects when the authoritative server frame arrives. Confirmation
is driven by the server's **echo-ack** (a 50 ms-debounced "your input up to frame N is now on
screen"), not the raw network ack. Password prompts get no predicted echo — suppression is
*emergent*: non-echoed input fails validation, kills its epoch, and keeps subsequent predictions
hidden, with no explicit password heuristic. Engagement is adaptive by SRTT with hysteresis (show
> 30 ms, flag/underline > 80 ms).

The port faithfully implements epoch-gated confirmation, adaptive engagement, flagging, glitch
escalation, and no-echo suppression. It predicts ASCII printables (with insert-mode row shift),
backspace, CR/LF, the left/right arrow keys (CSI **and** SS3/application-cursor form), and whole
UTF-8 graphemes including double-width CJK/emoji (cursor advances by two cells). Control/escape
sequences it doesn't model open a fresh epoch but make no concrete guess (they fall back to the
server's real echo). A wrong or unconfirmed guess is always reconciled away — it never corrupts the
display.

## Reconnect & detachable sessions

Sessions are **detachable**: the server keeps your shell (and its live screen) running after a
disconnect, keyed by your client endpoint id, so reconnecting from the same client drops you back
exactly where you left off. A detached session is reaped after `--session-ttl-secs` (default 24 h)
or immediately when its shell exits. There is one session per peer, one shell — no multiplexing.

The reconnect is **automatic and in-process**: the client doesn't exit when the link drops. A brief
outage (e.g. a phone screen-off — Android freezes the process, so QUIC keepalives stop) is ridden
out on the same connection thanks to a 5-minute connection idle timeout. A longer outage times the
connection out; the client then transparently re-dials and reattaches to the same server session,
holding the last screen under a `reconnecting…` banner in the meantime. A **wall-clock freeze
detector** turns a multi-minute wake-up hang into a ~1–2 s reattach: if real time jumps more than
20 s between two (≤50 ms-cadence) loop iterations, the client concludes the process was suspended,
drops the (almost certainly dead) connection, and re-dials immediately. A sub-20 s glance still
rides out silently on the existing connection.

> **`--direct` caveat:** transparent re-dial targets the *same* address it first dialed, so a
> `--direct <ip:port>` client can't reconnect if the server restarts on a new ephemeral **port**.
> The relay/discovery path (a bare endpoint id) re-dials by node id and reconnects across address
> changes — use it (or a fixed port) when you need reconnection to survive a server restart.

## Security internals

The full picture is in the [threat model](THREAT_MODEL.md). In brief, the relevant boundaries:

- **Authorization** is a node-id allowlist, the *sole* gate; the peer's Ed25519 node-id is
  authenticated by iroh's QUIC + TLS 1.3 handshake *by construction* (no TOFU window — the client
  pins the id it dialed). There is no "accept any peer" mode and no passphrase/PAKE second factor.
- **The data plane treats every authorized peer as untrusted**: a resize is clamped to `[2, 1000]`
  before any vt100 allocation; instruction inflation, fragment replay, reassembly bytes, and
  received-state accumulation are each explicitly bounded; the QUIC handshake and the 1-byte
  admission ack are deadline-bounded; and `vt100` (a dependency outside koh's no-panic coverage) is
  wrapped in `catch_unwind` on both sides so a crafted repaint drops a frame instead of crashing.
- **The identity key is always encrypted at rest** (`koh-key-v1`: Argon2id 64 MiB / 4 passes +
  AES-256-GCM, modeled on `openssh-key-v1`), with an enforced ≥12-char passphrase floor, written
  0600 via a born-private atomic write + `O_NOFOLLOW` read, and zeroized in memory. koh keeps every
  file it owns under `~/.config/koh` and nowhere else.
- The crate is `forbid(unsafe)` and denies the panic lint family (`unwrap`/`expect`/`panic`/
  indexing/slicing), with `overflow-checks` on in release too — so the panic-free-by-construction
  property holds against adversarial input.

## Testing tiers

You never need a second *machine* to develop koh — you need a second *process* and occasionally a
second *container*. The verification is layered cheapest-first; everything but Tier 3 is headless.

### Tier 0 — pure logic, no infra (`cargo test`)

The SSP, diff/apply, and predictor are network- and TTY-free, so they're tested deterministically:

- **State round-trip** — `apply(diff(base→target))` over `base` equals `target`, for screens (incl.
  wide chars / emoji / combining marks) and input.
- **Transport under chaos** (`ssp::testkit`) — two transports through a seeded
  lossy/latent/reordering/duplicating link; asserts convergence *and* that the newest applied state
  number never regresses (the no-head-of-line-blocking guard).
- **Terminal / predictor / PTY / fragmenter** — diff+resize, predict→confirm→clear,
  predict→no-echo→suppress, real-shell streaming, fragment supersede/reassemble.
- **Property tests** on the attacker-reachable parsers — `Transport::recv` over arbitrary envelopes,
  `FragmentAssembly::add` over adversarial sequences, `decrypt_key` over arbitrary payloads — assert
  never-panic and bounded. Plus coverage-guided fuzz targets (`screen_apply`, `wire_decode`).
- **Whole-stack chaos** — input + screen + transport + collapse + echo-ack over the simulated link:
  `cargo run --example chaos -- chaos --loss 0.5` (or `cargo test --test integration`).

### Tier 1 — two endpoints + a PTY on localhost, over *real* iroh (`cargo test`)

The big unlock, with **zero infrastructure**: a second host is just a second endpoint, and a TTY is
just an allocated PTY. Both are real and hermetic.

- **`transport_iroh` module tests** — two real iroh endpoints connect over loopback (relay-less,
  `bind_endpoint_local`) and exchange datagrams.
- **`tests/e2e_loopback.rs`** — the *entire* loop in one process: scripted keystroke → client → iroh
  datagram → server → PTY-hosted `sh` → vt100 → iroh → client render. Asserts the typed command's
  output round-trips.
- **`tests/e2e_pty_binary.rs`** — the **real `koh` binary** attached to an allocated PTY (so
  `isatty()` is true and raw-mode + termina run for real), driven by scripted keystrokes with
  rendered frames read back from the master, connected with `--direct` to an in-process server.
- **`tests/reattach.rs`** — the detachable-session acceptance test: type a marker, disconnect,
  reconnect from the *same* client endpoint, assert the session re-syncs to the persisted screen.
- **`tests/e2e_reconnect.rs`** — the auto-reconnect regression test: mid-session the server
  force-closes the connection while keeping the shell; asserts the client transparently re-dials,
  reattaches to the *same* shell, and keeps working.
- **`tests/exit_status.rs`** — a loopback session where `sh` runs `exit 42`; asserts the client
  observes exit code `42` on the shutdown frame.

The seam that makes this cheap: terminal I/O is abstracted behind `ClientTerminal`, so the same
session loop runs against the real termina path (binary) or a captured-cells mock (fast test).

### Tier 2 — Android emulator: runtime, network realism, resilience ([`testing/android/`](../testing/android/))

The layer a single in-process test can't reach: the **real `koh` binary on a real Android OS**,
driven over `adb`. Opt-in (`KOH_ANDROID_EMULATOR=1`), never part of `cargo test`. A **smoke** suite
proves the Android iroh/DNS path binds without the `ndk-context` panic (a runtime-only bug
cross-compilation can't catch); a **stress** suite hammers koh under load, churn, and adverse
conditions (connection churn, concurrent sessions, throughput + memory-longevity leak checks, signal
handling, a short screen-off freeze and a long one, reattach continuity, `tc netem`
loss/jitter/reorder beneath real QUIC, a total-outage roaming analogue, and a bare-id connection over
the public relay); and a **security** suite proves the data-plane and key defenses against a
cross-compiled malicious-peer harness.

### Tier 3 — real devices (manual)

A small final human acceptance pass: paste the endpoint id on an actual phone, connect to an actual
Mac over the public relay, type on a laggy cell link, and feel the predictions. The headless tiers
prove correctness; only a real two-device run over a real radio proves *feel* and migration.

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
