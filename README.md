# rmosh — mosh, rewritten in Rust over iroh

`rmosh` ("moshers") is a from-scratch Rust reimplementation of [mosh](https://mosh.org)
(the mobile shell) whose transport is **[iroh](https://iroh.computer) peer-to-peer QUIC**
instead of mosh's UDP/OCB. It gives you mosh's signature feel — instant local echo on laggy
links, survival across suspend/resume and IP changes, no head-of-line blocking — while iroh
handles encryption, NAT traversal, relay fallback, connection migration, and RTT.

It is the transport+terminal core for an eventual Bevy-based Android terminal for vibe-coding
over your phone to your main PC. This repo is that core: two binaries, `rmosh-server` and
`rmosh-client`, that give you a real remote shell by endpoint id.

> Status: the protocol core, terminal model, PTY host, predictor, and iroh transport are
> implemented and tested. 40 tests pass, including property tests, a network-chaos simulator,
> and a full in-process client↔server integration scenario that converges at 50% packet loss.

## The one idea

rmosh is **not a tunnel**. It does not ship a byte stream. It is a *state-synchronization*
system whose payload happens to be a terminal. Each side holds an authoritative object and the
protocol's only job is to bring the peer to the **latest** version of it — intermediate states
are collapsed and discarded. If the screen changed 100 times in 40ms, only the final state is
sent. This is the source of every property users love: instant re-sync after a drop (never
replay a backlog), responsiveness on lossy links, and no head-of-line blocking.

## Architecture

A Cargo workspace of small, independently-tested crates:

```
crates/
├── wire/            SSP instruction envelope, postcard codec, fragmenter/reassembler
├── ssp/             SyncState trait + generic Transport<Local,Remote> + send scheduler
│                      + a deterministic lossy/reordering chaos sim harness (testkit)
├── terminal/        TerminalScreen state (vt100-backed) + ServerTerminal live emulator
├── input/           UserInput state: keystrokes + resize as an append-only synced log
├── predict/         local-echo prediction engine (overlays, epochs, adaptive engage)
├── transport-iroh/  iroh endpoint setup, persistent identity, datagram channel, RTT
├── pty/             PTY allocation, shell spawn, SIGWINCH, child reaping
├── server/          rmosh-server: PTY + emulator + Transport<Screen,Input> over iroh
└── client/          rmosh-client: input + Transport<Input,Screen> + predictor + render
xtask/               in-process integration + network-chaos drivers
```

Dependency direction is strict: `wire ← ssp ← {terminal, input}`, with `predict` over
`{terminal, input}`, `transport-iroh` over `wire`, and the binaries on top. Only
`transport-iroh`, `server`, and `client` touch iroh — the entire protocol (`ssp`, `terminal`,
`input`, `predict`, `wire`) is transport-agnostic and tested with no network at all.

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

## Two design decisions called out by the spec

### Fragmentation (how oversized state crosses the wire)

**rmosh ships the SSP over QUIC *unreliable datagrams*, never a reliable stream for the steady
flow** — a reliable ordered stream would reintroduce head-of-line blocking and defeat the
"drop superseded state" property. We use mosh's own approach **(option a): a fragmenter**.
A serialized instruction larger than the path MTU is split into datagram-sized `Fragment`s
that share an id; the reassembler keeps only the highest id it has seen, so a newer
instruction's fragments supersede and discard any stale partial — the drop-superseded property
extends down to the framing layer. Identical retransmits reuse fragment ids so a partially
received instruction can complete across retransmissions. The datagram budget is taken from
`Connection::max_datagram_size()` (re-queried, since it tracks the path MTU).

`IrohChannel` also exposes a one-shot reliable uni-stream (`send_reliable`/`recv_reliable`) as
an escape hatch for very large repaints; the default path uses the fragmenter, which the chaos
tests exercise down to a 30-byte MTU at 30% loss.

### Authorization (who gets a shell)

On iroh, identity is the endpoint's public key. rmosh deliberately does **not** copy
iroh-ssh's "anyone with the endpoint id gets a shell" model. The server:

- uses a **persistent secret key** (so its endpoint id is stable across restarts), and
- **allowlists client endpoint ids** — a connection is served only if the client's id is on
  the `--allow` list. `--allow-any` exists for local testing and prints a loud warning.

QUIC/iroh already authenticates both ends by public key and encrypts everything; the allowlist
is the authorization layer on top.

## Build

```sh
cargo build --release          # builds rmosh-server and rmosh-client
cargo test  --workspace        # 40 tests: unit, property, chaos sim, integration
```

Pinned toolchain-adjacent versions live in the root `Cargo.toml`: `iroh =1.0.0` (which brings
its own QUIC backend, `noq`, a quinn fork — we never depend on quinn directly), `vt100 0.16`,
`portable-pty 0.9`, `crossterm 0.29`, `postcard 1.1`.

## Run a session by endpoint id

On the **server** (your PC). First find out the client's id, then authorize it:

```sh
# on the client machine, print its stable endpoint id:
rmosh-client --show-id
#   3f9c…(64 hex chars)

# on the server, allow that client and start:
rmosh-server --allow 3f9c…
# ┌─ rmosh-server ready ──────────────────────────────────────
# │ endpoint id : 871b…
# │ connect     : rmosh-client 871b…
# └───────────────────────────────────────────────────────────
```

On the **client** (your phone/laptop), connect by the server's endpoint id:

```sh
rmosh-client 871b…
# connected. (Ctrl-^ then . to disconnect)
```

The server's identity persists in `~/…/rmosh/server.key` (override with `--key-file`); the
client's in `~/…/rmosh/client.key`. Prediction policy is `--predict adaptive|always|never`
(default adaptive: it engages only when the link is slow enough to benefit). Set
`RMOSH_LOG=/tmp/rmosh.log` to capture client logs without disturbing the TUI.

For session persistence across reconnects, run `tmux` inside the session — rmosh intentionally
does no multiplexing (one session, one shell), exactly like mosh.

## The predictor

The client guesses what each keystroke does to the screen and shows it immediately (underlined
on high-RTT links), then confirms or corrects when the authoritative server frame arrives.
Confirmation is driven by the server's **echo-ack** (a 50ms-debounced "your input up to frame
N is now on screen"), not the raw network ack. Password prompts get no predicted echo —
suppression is *emergent*: non-echoed input fails validation, kills its epoch, and keeps
subsequent predictions hidden, with no explicit password heuristic. Engagement is adaptive by
SRTT with hysteresis (show > 30ms, flag/underline > 80ms).

The port faithfully implements epoch-gated confirmation, adaptive engagement, flagging, glitch
escalation, and no-echo suppression. To stay tractable it predicts in overwrite mode for ASCII
printables, backspace, and CR/LF; control/escape/CSI and non-ASCII input open a fresh epoch but
make no concrete guess (they fall back to the server's real echo). A wrong or unconfirmed guess
is always reconciled away — it never corrupts the display.

## Testing

- **State round-trip** — `apply(diff(base→target))` over `base` equals `target`, for screens
  (incl. wide chars / emoji / combining marks) and input.
- **Transport under chaos** (`ssp::testkit`) — two transports through a seeded
  lossy/latent/reordering/duplicating link; asserts convergence *and* that the newest applied
  state number never regresses (the no-head-of-line-blocking guard).
- **Terminal** — diff/apply + resize repaint + equality.
- **Predictor** — predict→confirm→clear, predict→no-echo→suppress, adaptive show/hide.
- **PTY** — spawns real shells, streams output, echoes input, resizes.
- **Integration** (`xtask`) — the full client↔server stack (input + screen + transport +
  collapse + echo-ack) end-to-end over the chaos link:
  `cargo run -p xtask -- chaos --loss 0.5` / `cargo run -p xtask -- integration`.

## Acceptance criteria (mosh feel)

| Property | How rmosh delivers it |
|---|---|
| Keystrokes appear instantly on high-RTT links | predictor (adaptive, underlined, then confirmed) |
| Survives suspend/resume + IP change, re-syncs to current screen | QUIC connection migration + SSP re-sync to latest (no backlog) |
| A burst of superseded output never delays the current screen | datagram transport + state collapse; proven by the chaos monotonicity guard |
| Password prompts show no predicted echo | emergent no-echo suppression in the predictor |
| Reconnect lands you where the screen is *now* | SSP always diffs toward the latest state |

## Non-goals / divergences

- **No wire compatibility with upstream mosh** (impossible over iroh; we use postcard, not
  protobuf, and drop OCB/heartbeats/chaff).
- **No multiplexing** — one session, one shell; use tmux.
- iroh-ssh was a reference for the iroh bootstrap only, not a base to extend.
- Terminal *replies* (DSR/DA query responses the shell expects back) are not yet synthesized;
  most interactive apps are fine, some may probe. Title/bell propagate; OSC-52 clipboard does
  not yet.

## Roadmap

This core is the foundation for a 100%-Rust mobile (Android) terminal — likely Bevy-based —
that vibe-codes over rmosh to your main PC. Natural next steps: the reliable-stream path for
huge repaints, terminal-reply synthesis, scrollback sync, and a Bevy front-end reusing
`terminal` + `input` + `predict` + `transport-iroh` directly.

## License

GPL-3.0-or-later (matching upstream mosh).
