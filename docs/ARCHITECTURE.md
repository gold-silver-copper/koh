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

A workspace of two crates. `koh-core` is the library, with everything except the command line;
it has no clap, so its `Cargo.toml` forbids the panic lints outright. `koh` is the binary: the clap
definitions and the mapping from arguments to `koh-core`'s config structs. Its lints are the same
set at `deny`, because clap's derives `allow` some of them.

```
src/                 the `koh` binary
├── main.rs          serve / connect / id / key dispatch, and the hidden `__launch`
└── args.rs          the clap argument structs and their conversions into koh-core's configs
tests/               the binary on a PTY, upgrade in place, key creation races, Android (opt-in)
koh-core/src/
├── lib.rs           crate root: module declarations + the architecture overview
├── proto.rs         the koh/3 wire protocol: client messages, screen frames, caps, pacing
├── terminal/        TerminalScreen (a cell grid + structured diff) + ServerTerminal (fux-vt)
├── predict.rs       local-echo prediction engine (overlays, epochs, adaptive engage)
├── transport_iroh/  iroh endpoint setup, the identity key file, connection handle, admission
├── pty.rs           PTYs over fuxix, the `__launch` launcher sessions start through, reaping
├── server/          session tasks + registry, the per-connection loop (ServerConn), `serve`
├── client/          the connection loop + ClientSession core + predictor + render + `connect`
│   └── backend/     KohBackend (escape emission) + Tty (raw mode and size through fuxix::terminal)
├── identity.rs      unlocked identities + the key lease `koh key reset` respects
├── log.rs           the `RUST_LOG` filter `serve` and `connect` install (`target=level` directives)
├── idcmd.rs         `koh id` — print this machine's endpoint id
├── keycmd.rs        `koh key` — show the identity, or reset it
└── bin/koh-launch.rs the launcher koh-core's tests start sessions through (not published)
koh-core/tests/net/  koh over a fault-injecting link between real iroh endpoints
koh-core/tests/      PTYs, sessions, loopback e2e and admission tests
```

Dependency direction is strict: `proto` sits on `terminal`; `server` and `client` (+ the `koh`
binary) build on both. The protocol cores (`proto`, `terminal`, `predict`, `server::ServerConn`,
`client::ClientSession`) do no I/O and are tested with no network at all. `predict` imports nothing
from `crate::` (CI checks it), so it is a standalone terminal-prediction library.

## The protocol (koh/3)

The ALPN `koh/3` is the version check: a peer on another version fails the TLS handshake with a
clear error. After the handshake the server checks the allowlist and opens a bi-stream carrying one
ADMIT byte, so a rejected client can tell "not authorized" from a network error. Then
(`koh-core/src/proto.rs`):

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

A session is one PTY + emulator per authorized peer (`server::session`). Its program starts
through the launcher, `koh __launch PROGRAM ARGS…`: making a program a session leader with the
PTY as its controlling terminal needs code between `fork` and `exec`, which std allows only
through `unsafe`, so the launcher does it as a program of its own. It marks every inherited
descriptor close-on-exec, calls `setsid`, takes the PTY as its controlling terminal and `exec`s
the program, reporting a failure (including a failed `exec`) on a pipe the `exec` closes. On
Linux the launcher is `/proc/self/exe`, so a server whose binary was upgraded in place still
launches sessions; `__launch`'s interface is fixed for the same reason. Two connections from the
same peer can briefly share it, when a reconnect races the old connection's teardown, so the
per-connection state never lives in the session:

- **Echo-ack is per connection.** Input sequence numbers are per connection, so the input
  history and the 50 ms debounce live in the per-connection `ServerConn` (`server::EchoAck`), not
  in the session, and each frame carries its connection's own echo-ack. A session-global ack would
  hand one connection another's numbers, and its predictor would treat every keystroke as already
  acked.
- **A change wakes every connection.** The session task publishes each new screen on a
  `tokio::sync::watch`; each connection holds a receiver and `select!`s on it. Every connection
  wakes on one change; a burst coalesces into the latest screen; and a change landing between a
  connection's read and its wait is never lost, because the receiver keeps the latest value.
- **Detach on drop.** A connection holds a `SessionClient`; dropping it (on return **or**
  panic) sends the session task a detach, so a panicking connection can't pin a session. The
  session task counts attached clients and starts the TTL only when the last one leaves; it tears
  itself down at the TTL or once its shell exits, and tells the registry to forget it.
- **The bell hook.** `--on-bell <cmd>` / `ConnectConfig::bell_command` runs `sh -c` when
  the remote bell count climbs: detached (fds on `/dev/null`), `KOH_*` scrubbed except
  `KOH_BELL_COUNT` / `KOH_TITLE`, rate-limited to one spawn per second with bursts coalesced, the
  child reaped off the session loop. The decision is a pure `BellHook::observe`.
- **The hook's environment and its first frame.** `BellHook::command(count, title,
  parent_env)` builds the child from an explicit parent environment (`env_clear`, then everything
  but `KOH_*`, sharing `pty::is_koh_env_key` with the PTY spawn), so the scrub is tested with a
  synthetic environment rather than assumed. The bell count is cumulative per server session, so
  the first synced frame `prime`s the hook: bells from before this attach do not fire it. The hook
  outlives a reconnect and is not re-primed, so bells during an outage do.

The client renders through `client::ClientTerminal`, so tests can capture frames instead of
driving a real terminal, and the predictor reads screens through `predict::ScreenView`
(implemented for the client `Grid` and for `fux_vt::Screen`), which keeps `predict.rs` free of
`crate::` imports.

## Security internals

The full picture is in the [threat model](THREAT_MODEL.md). In brief, the relevant boundaries:

- **Authorization** is a node-id allowlist, the *sole* gate; the peer's Ed25519 node-id is
  authenticated by iroh's QUIC + TLS 1.3 handshake *by construction* (no TOFU window — the client
  pins the id it dialed). There is no "accept any peer" mode and no passphrase/PAKE second factor.
- **The data plane treats every authorized peer as untrusted**: a resize is clamped to `[2, 1000]`
  before any grid allocation; client messages and frames are size-capped and frames inflate under a
  limit; each end keeps a fixed window of screens; QUIC stream limits and flow control bound what is
  in flight; the QUIC handshake and the 1-byte admission ack are deadline-bounded; and a screen
  diff is fully validated before it is applied, with no terminal parser on the client (the
  server's fux-vt emulator is panic-free and bounded).
- **The identity key is protected by its file permissions**, like an SSH host key: the file is the
  raw 32-byte secret, created 0600 by a born-private atomic write, read with `O_NOFOLLOW` and
  re-tightened to 0600 through the open descriptor. Anyone who can read the file is that identity.
  koh keeps every file it owns under `~/.config/koh` and nowhere else.
- The crate is `forbid(unsafe)` and forbids the panic lint family (`unwrap`/`expect`/`panic`/
  indexing/slicing), unchecked arithmetic (`arithmetic_side_effects`) and lossy `as` casts in
  production code, with `overflow-checks` on in release too — so the panic-free-by-construction
  property holds against adversarial input.

## Testing tiers

You never need a second *machine* to develop koh — you need a second *process* and occasionally a
second *container*. The verification is layered cheapest-first; everything but Tier 3 is headless.

### Tier 0 — pure logic, no infra (`cargo test --workspace`)

The protocol, diff/apply, predictor and session registry need no network or TTY, so they're tested
deterministically:

- **State round-trip** — `apply(diff(base→target))` over `base` equals `target`, for screens (incl.
  wide chars / emoji / combining marks).
- **Protocol cores** — `ClientSession` and `ServerConn` driven with synthesized frames and
  messages: bases, acknowledgements, resyncs, the frame window, pacing, retries, heartbeats,
  backpressure and shutdown; `proto` round-trips, size caps, truncation and inflate bombs.
- **Terminal / predictor** — diff+resize, predict→confirm→clear, predict→no-echo→suppress.
- **Property tests and fuzzing** on the attacker-reachable parsers — assert never-panic and bounded.
  Coverage-guided fuzz targets: `screen_apply` (the structured diff), `server_process` and
  `proto_decode` (both directions of the wire).

### Tier 1 — real iroh endpoints on one machine (`cargo test --workspace`)

A second host is just a second endpoint, and a TTY is just an allocated PTY.

- **`koh-core/tests/net/`** — a real `koh serve` accept loop and a real `koh connect` client loop on iroh
  endpoints whose only path is an in-process fault-injecting link (`koh-core/tests/net/link.rs`, an iroh
  custom transport): loss, delay, jitter, duplication, reordering and outages under real QUIC. It
  covers screen convergence (and that a stale screen is never shown), exactly-once ordered input,
  reattach, a forced mid-session drop, exit status, resize, XON/XOFF, input backpressure, the bell
  hook, prediction and the no-echo property, and hostile clients and servers. An `#[ignore]`d
  baseline measures echo latency, output bursts, bytes and outage recovery per network profile.
- **`koh-core/tests/pty.rs`** and **`koh-core/tests/sessions.rs`** — real programs on real PTYs,
  started through the `koh-launch` binary: output streaming and teardown, exit statuses, the
  reaped-PID gate, a program that cannot start, no leaked descriptors, a session leader owning its
  terminal; the session registry's attach/reattach/cap/TTL/teardown; `run_session` and the
  per-connection echo-ack over loopback iroh.
- **`koh-core/tests/e2e_loopback.rs`** — the whole loop over loopback: scripted keystroke → client → iroh →
  server → PTY-hosted `sh` → fux-vt → iroh → client render.
- **`tests/e2e_pty_binary.rs`** — the **real `koh` binary** attached to an allocated PTY (so
  `isatty()` is true and raw mode runs for real), driven by scripted keystrokes with rendered
  frames read back from the master, connected with `--direct` to an in-process server; and the
  `Ctrl-^ Ctrl-Z` suspend under a job-control bash.
- **`tests/upgrade_in_place.rs`** (Linux) — a running `koh serve` whose binary file is removed
  still starts sessions, because it launches them from `/proc/self/exe`.

Terminal I/O is behind `ClientTerminal`, so the same session loop runs against the real terminal
(binary) or a capturing mock (tests). One layer down, `client::backend::KohBackend`'s provided
methods emit all the ANSI, so the bytes are pinned by tests against a capturing backend.

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
| Keystrokes appear instantly on every link | predictor (engages above 60 ms RTT once the server proves it echoes; confirmed by later frames) |
| Survives suspend/resume + IP change, re-syncs to current screen | QUIC connection migration + a fresh frame against an acknowledged base (no backlog) |
| A burst of superseded output never delays the current screen | one stream per frame, older frames reset; only the latest screen is sent |
| Password prompts show no predicted echo | emergent no-echo suppression in the predictor |
| Reconnect lands you where the screen is *now* | a new connection starts from the blank screen and gets the current one |
| Detach and reattach later, shell still running | server-side detachable sessions keyed by client id (reattach test) |
| Interactive apps (vim/htop/fzf) that probe the terminal work | server synthesizes DSR/DA/DECRQM replies |
| Client exits with the remote shell's status | exit code rides the final frame (`tests/net` session test) |
| `Ctrl-^ Ctrl-Z` suspends like a terminal's suspend key | the client sends itself SIGTSTP, so the shell reports it "Stopped" and `fg` resumes (`tests/e2e_pty_binary.rs`) |
