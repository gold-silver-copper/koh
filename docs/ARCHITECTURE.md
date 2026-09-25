# koh architecture

How koh is built. The [README](../README.md) covers what it does and how to use it; this is the
internals. Pair it with the [threat model](THREAT_MODEL.md) and the porting-research notes under
[`research/`](research/).

## The one idea

koh keeps a **copy of the server's screen** on the client, not a byte stream from the shell. The
server runs the terminal emulator; the client only ever receives screens, as diffs against a screen
it already holds, and a newer screen replaces an older one. If the screen changed 100 times in
40 ms, the client gets the latest, not 100 updates. That gives instant re-sync after a drop (never a
backlog), responsiveness on lossy links, and no head-of-line blocking of the screen behind stale
output. Keystrokes are the opposite: every byte matters and order matters, so they travel on one
reliable, ordered stream. QUIC (through iroh) provides both, plus encryption, authentication, loss
recovery, congestion control, RTT estimates, roaming and NAT traversal.

## Module layout

A single crate, organized into small, independently-tested modules:

```
src/
├── lib.rs           crate root: module declarations + the architecture overview
├── main.rs          the `koh` binary: serve / connect / id / key subcommand dispatch
├── wire.rs          SSP instruction envelope, postcard codec, fragmenter/reassembler
├── ssp/             SyncState trait + generic Transport<Local,Remote> + send scheduler
│                      + a deterministic lossy/reordering chaos sim harness (testkit)
├── terminal/        TerminalScreen state (a cell grid + structured diff) + ServerTerminal (fux-vt)
├── input.rs         UserInput state: keystrokes + resize as an append-only synced log
├── predict.rs       local-echo prediction engine (overlays, epochs, adaptive engage)
├── transport_iroh/  iroh endpoint setup, encrypted identity, datagram channel, RTT, admission
├── pty.rs           PTY allocation, shell spawn, SIGWINCH, child reaping
├── server/          PTY + emulator + Transport<Screen,Input> over iroh + `serve`
├── client/          input + Transport<Input,Screen> + predictor + backend-agnostic render + `connect`
│   └── backend/     the KohBackend seam: termina (default) / crossterm / qwertty behind cargo features
├── identity.rs      unlocked identities + the key lease `koh key reset` respects
├── args.rs          the clap argument structs (`cli` feature only)
├── idcmd.rs         `koh id` — print this machine's endpoint id
├── keycmd.rs        `koh key` — change the passphrase, show info, reset the identity
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

## The protocol (koh/3)

The ALPN `koh/3` is the version check: a peer on another version fails the TLS handshake with a
clear error. After the handshake the server checks the allowlist and opens a bi-stream carrying one
ADMIT byte, so a rejected client can tell "not authorized" from a network error. Then
(`src/proto.rs`):

- **Client to server: one uni stream** of length-prefixed postcard `ClientMsg`s: `Input { seq,
  bytes }` (at most 64 KiB; a paste is split), `Resize`, `Ack { frame }` after applying a frame, and
  `Resync` when a frame's base is unknown. `seq` numbers each input on the connection.
- **Server to client: one uni stream per `Frame`**, DEFLATE-compressed and inflated with a 16 MiB
  limit. A frame carries `num`, `base`, `echo_ack` and a `ScreenDiff` from frame `base` to frame
  `num`. Frame 0 is the blank default screen, which both ends always hold; real frames count from 1.
- **Bases are acknowledged frames.** The server diffs against the newest frame the client has
  acknowledged, so a lost frame only delays the screen until the next one. When the server sends a
  frame it resets the streams of older unacknowledged frames, so QUIC never retransmits a screen a
  newer one has replaced.
- **Pacing:** a frame goes out when the screen or the echo-ack changed, at most once per frame
  interval (`clamp(rtt / 2, 20 ms, 250 ms)`), and a heartbeat frame at least every 3 s so the
  client can tell a quiet session from a dead link.
- **Retries without QUIC's backoff:** on a lossy, jittery path QUIC's probe timeout is several
  round trips and doubles on each loss. So an unacknowledged newest frame is resent, as a new frame
  that supersedes it, after a round trip plus a frame interval; and input the echo-ack has not
  confirmed after the same wait makes the client send a repeated `Ack`, a later packet that lets
  QUIC detect the loss and retransmit at once.
- **Bounded state:** each end keeps at most `FRAME_WINDOW` (16) recent screens — the client its
  last applied frames, the server the frames sent since the last acknowledged one. That constant,
  plus QUIC flow control and the stream limits (the server accepts one client stream; the client a
  handful of frame streams), is the whole memory bound; a peer cannot make either end accumulate.
- **Backpressure:** PTY input goes through a bounded writer queue. While it is full the server
  stops reading the client's stream, QUIC flow control stops the client's writes, and the client
  keeps at most 1 MiB of typing before dropping it with an "input paused" status line. The keyboard
  loop never waits on the network, so `Ctrl-^ .` always works.
- **Shutdown:** when the shell exits, the server sends the final frame (carrying the exit code),
  waits up to 1 s for its ack, then closes the connection with code 0 and reason `session ended`.

`TerminalScreen` is a plain `Grid` of `fux_vt::Cell`s (with a cursor, per-row soft-wrap flags and
the input modes the client mirrors) plus the side channels: title, icon, OSC 52 clipboard, bell count
and exit code. The server's live emulator is `fux_vt::Parser` (`ServerTerminal`), with fux-vt's
opt-in events (title, icon, bell, clipboard) and extended replies (DECRQM, DECXCPR, secondary DA)
turned on. The diff (`ScreenDiff`) carries every changed row whole as run-length-encoded cells, the
cursor and the modes; after a resize the client starts from a blank grid and receives every
non-blank row. The client validates and copies cells and never runs a terminal parser, so server
bytes never reach one.

## Headless drivers (the protocol is I/O-free; the shells are thin)

Both ends split into a synchronous, I/O-free core and a thin async shell. The client's
**`ClientSession`** (`client/session.rs`) holds the recent screens, the predictor and the
escape/render state, and exposes pure steps: `on_input` (the `Ctrl-^`-prefix machine, prediction
seeding, input queueing), `on_frame`, `on_resize` and `on_tick` (the link-down and input-paused
banners), with the outgoing messages taken from a queue. The server's **`ServerConn`**
(`server/mod.rs`) decodes the client's stream, tracks the echo-ack, and decides which frame to
send against which base. None of it touches tokio, iroh or a terminal, and time is an argument, so
both are deterministically unit-testable. The shells own the `tokio::select!` (the client's kept
`biased` for input priority), a writer task for the client's stream, a task per frame stream, and
the rendering.

On the server side, **PTY writes are non-blocking**: a dedicated `koh-pty-writer` thread owns the
blocking write handle and drains a bounded channel, so forwarding a keystroke (or a synthesized
DSR/DA reply) only enqueues and never blocks a tokio worker on a slow child. Both producers share
one sender and enqueue under the session lock, so byte order is preserved (a query reply can't
overtake the keystroke that triggered it).

## The predictor

The client guesses what each keystroke does to the screen and shows it immediately (underlined on
high-RTT links), then confirms or corrects when the authoritative server frame arrives. Confirmation
is driven by the server's **echo-ack** (a 50 ms-debounced "your input up to frame N is now on
screen"), not the raw network ack. Password prompts get no predicted echo — suppression is
*emergent*: non-echoed input fails validation, kills its epoch, and keeps subsequent predictions
hidden, with no explicit password heuristic. Prediction is **always on** in koh (`DisplayPreference::
Always`), so keystrokes engage on every link; the engine also implements an adaptive-by-SRTT
engagement mode that the client no longer selects. The underline *flagging* stays SRTT-gated
(> 80 ms) with hysteresis.

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

## Sessions, connections and the bell hook

A session is one PTY + emulator per authorized peer (`server::session`). Two connections from the
same peer can briefly share it, when a reconnect races the old connection's teardown, so the
per-connection state never lives in the session:

- **KS-02 — echo-ack is per connection.** Input sequence numbers are per connection, so the input
  history and the 50 ms debounce live in the per-connection `ServerConn` (`server::EchoAck`), not
  in the emulator, and each frame carries its connection's own echo-ack. A session-global ack would
  hand one connection another's numbers, and its predictor would treat every keystroke as already
  acked.
- **KS-03 — a change wakes every connection.** `SessionHandle::changed` is a `ChangeSignal`, a
  `tokio::sync::watch` version counter: the PTY drain task `pulse`s it, and each attached loop holds
  its own receiver and `select!`s on `changed()`. Every loop wakes on one pulse; a burst coalesces
  into one wake per loop; and because a receiver remembers the version it last saw, a pulse landing
  between a loop's snapshot and its wait is never lost.
- **K-16 — the unwind guard.** `AttachGuard` holds the session store and the peer id and runs the
  balancing `detach` if a connection task unwinds before its explicit detach/reap, so a panicking
  task can't pin a session with `attached > 0` forever. `attached` is a refcount across the peer's
  connections; the TTL reaper collects a session only at zero, or once its shell has exited.
- **KB-01 — the bell hook.** `--on-bell <cmd>` / `ConnectConfig::bell_command` runs `sh -c` when
  the remote bell count climbs: detached (fds on `/dev/null`), `KOH_*` scrubbed except
  `KOH_BELL_COUNT` / `KOH_TITLE`, rate-limited to one spawn per second with bursts coalesced, the
  child reaped off the session loop. The decision is a pure `BellHook::observe`.
- **KB-02 — the hook's environment and its first frame.** `BellHook::command(count, title,
  parent_env)` builds the child from an explicit parent environment (`env_clear`, then everything
  but `KOH_*`, sharing `pty::is_koh_env_key` with the PTY spawn), so the scrub is tested with a
  synthetic environment rather than assumed. The bell count is cumulative per server session, so
  the first synced frame `prime`s the hook: bells from before this attach do not fire it. The hook
  outlives a reconnect and is not re-primed, so bells during an outage do.

The client renders through `client::ClientTerminal`, so tests can capture frames instead of
driving a real terminal, and the predictor reads screens through `predict::ScreenView`
(implemented for the client `Grid` and for `fux_vt::Screen`), which keeps `predict.rs` free of
`crate::` imports.
`ssp::testkit::GridState` is a non-terminal state with multi-datagram diffs that exercises the SSP
on its own.

## Security internals

The full picture is in the [threat model](THREAT_MODEL.md). In brief, the relevant boundaries:

- **Authorization** is a node-id allowlist, the *sole* gate; the peer's Ed25519 node-id is
  authenticated by iroh's QUIC + TLS 1.3 handshake *by construction* (no TOFU window — the client
  pins the id it dialed). There is no "accept any peer" mode and no passphrase/PAKE second factor.
- **The data plane treats every authorized peer as untrusted**: a resize is clamped to `[2, 1000]`
  before any grid allocation; instruction inflation, fragment replay, reassembly bytes, and
  received-state accumulation are each explicitly bounded; the QUIC handshake and the 1-byte
  admission ack are deadline-bounded; and a screen diff is fully validated before it is applied,
  with no terminal parser on the client (the server's fux-vt emulator is panic-free and bounded).
- **The identity key is always encrypted at rest** (`koh-key-v1`: Argon2id 64 MiB / 4 passes +
  AES-256-GCM, modeled on `openssh-key-v1`), with an enforced ≥12-char passphrase floor, written
  0600 via a born-private atomic write + `O_NOFOLLOW` read, and zeroized in memory. koh keeps every
  file it owns under `~/.config/koh` and nowhere else.
- The crate is `forbid(unsafe)` and forbids the panic lint family (`unwrap`/`expect`/`panic`/
  indexing/slicing), unchecked arithmetic (`arithmetic_side_effects`) and lossy `as` casts in
  production code, with `overflow-checks` on in release too — so the panic-free-by-construction
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
  never-panic and bounded. Plus coverage-guided fuzz targets (`screen_apply` over the structured diff,
  `server_process`, `wire_decode`).
- **Whole-stack chaos** — input + screen + transport + collapse + echo-ack over the simulated link:
  `cargo run --example chaos -- chaos --loss 0.5` (or `cargo test --test integration`).

### Tier 1 — two endpoints + a PTY on localhost, over *real* iroh (`cargo test`)

The big unlock, with **zero infrastructure**: a second host is just a second endpoint, and a TTY is
just an allocated PTY. Both are real and hermetic.

- **`transport_iroh` module tests** — two real iroh endpoints connect over loopback (relay-less,
  `bind_endpoint_local`) and exchange datagrams.
- **`tests/e2e_loopback.rs`** — the *entire* loop in one process: scripted keystroke → client → iroh
  datagram → server → PTY-hosted `sh` → fux-vt → iroh → client render. Asserts the typed command's
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
session loop runs against the real backend path (binary) or a captured-cells mock (fast test). One
layer down, the *rendering* is abstracted again behind `client::backend::KohBackend` — the escape
emission has no dependency on any specific terminal crate (its default methods write standard ANSI),
so `termina` (default), `crossterm`, and `qwertty` are interchangeable at build time and a new backend
only wires up raw-mode + size.

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
| Keystrokes appear instantly on every link | predictor (always on; underlined on high-RTT links, then confirmed) |
| Survives suspend/resume + IP change, re-syncs to current screen | QUIC connection migration + a fresh frame against an acknowledged base (no backlog) |
| A burst of superseded output never delays the current screen | one stream per frame, older frames reset; only the latest screen is sent |
| Password prompts show no predicted echo | emergent no-echo suppression in the predictor |
| Reconnect lands you where the screen is *now* | a new connection starts from the blank screen and gets the current one |
| Detach and reattach later, shell still running | server-side detachable sessions keyed by client id (reattach test) |
| Interactive apps (vim/htop/fzf) that probe the terminal work | server synthesizes DSR/DA/DECRQM replies |
| Client exits with the remote shell's status | exit code rides the final frame (`tests/net` session test) |
