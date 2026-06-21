# Port notes: detachable/reattachable server sessions + QUIC keepalive/idle-timeout (mosh parity)

Scope: what `moshers` actually does, what `moshers2` actually does, and a concrete refactor
plan for `moshers2`. All quotes are from the actual source on disk (paths absolute). Where I
could not verify something I say so explicitly.

Versions verified: `moshers2` pins `iroh = "=1.0.0"`
(`/Users/kisaczka/Desktop/code/moshers2/Cargo.toml:37`), and `Cargo.lock` resolves
`name = "iroh" / version = "1.0.0"`. The iroh API quotes below are read from the extracted
crate at
`/Users/kisaczka/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/iroh-1.0.0/`.

---

## 1. Does `moshers` implement DETACHABLE sessions?

**NO. Neither `moshers` nor `moshers2` has server-side detachable/reattachable sessions.**
In both, the PTY+emulator lifetime is bound 1:1 to a single QUIC `Connection`; client
disconnect kills the shell.

### `moshers`: "detach" is purely client-side; the server kills the shell

The only "detach" in `moshers` is a *client* key escape that closes the connection. There is
no session store, no session id, no re-attach path, no TTL/reaping.

Client side (`/Users/kisaczka/Desktop/code/moshers/crates/moshers-client/src/session.rs`):

```rust
/// Ctrl-^ (0x1e): the detach escape lead-in.
pub const ESCAPE: u8 = 0x1e;
```
```rust
/// Run the client session until the user detaches (Ctrl-^ `.`), the input source ends,
/// or the connection closes. `output` receives the escape sequences to render.
```
and at the end it just closes:
```rust
conn.close(0u32.into(), b"client detached");   // session.rs:151
```

Server side (`/Users/kisaczka/Desktop/code/moshers/crates/moshers-server/src/main.rs`): a
single accept loop runs **one session at a time** (no `tokio::spawn`), and `serve_session`
spawns one PTY, loops on that one `conn`, and on exit unconditionally kills the PTY:

```rust
loop {
    let conn = endpoint::accept_authorized(&ep, &allow).await?;   // main.rs:84
    ...
    if let Err(e) = serve_session(conn).await { ... }            // main.rs:107
    ...
}
```
```rust
async fn serve_session(conn: Connection) -> Result<()> {        // main.rs:114
    ...
    let mut pty = Pty::spawn(init_cols, init_rows).context("spawn pty")?;
    ...
    let result = loop {
        ...
        res = conn.read_datagram() => {
            match res {
                Ok(bytes) => apply_client_input(...),
                Err(e) => break Err(...anyhow!("connection closed: {e}")),  // main.rs:163
            }
        }
        ...
    };
    pty.kill();                                                  // main.rs:182  <-- shell dies on disconnect
    conn.close(0u32.into(), b"session ended");
    result.map(|_| ())
}
```

So in `moshers`: connection drop -> `read_datagram()` errors -> loop breaks -> `pty.kill()`.
The shell does **not** survive, and there is nothing to re-attach to. (`moshers` also can't
serve two clients concurrently — its loop is serial.)

`grep -rniE "detach|reattach|session.?store|session.?registry|session.?id|HashMap.*Session|resume|survive"`
over `moshers/crates` returns only: the client-side Ctrl-^ escape strings above. No
server-side registry exists.

### `moshers2`: same — `run_session` is per-connection and kills the shell on disconnect

`/Users/kisaczka/Desktop/code/moshers2/crates/server/src/lib.rs` (`run_session`): one PTY +
one `ServerTerminal` (`emu`) created per call, bound to the one `conn`. On peer close it
breaks the loop and kills:

```rust
dg = channel.recv() => {
    match dg {
        Ok(bytes) => { ... }
        Err(e) => {
            info!(reason = %e, "connection closed by peer");
            break;                                              // lib.rs:89
        }
    }
}
```
```rust
channel.close(0, b"session ended");                            // lib.rs:121
let _ = pty.kill();                                            // lib.rs:122  <-- shell dies on disconnect
Ok(())
```

`/Users/kisaczka/Desktop/code/moshers2/crates/server/src/main.rs` does `tokio::spawn` per
incoming connection (so it *can* serve concurrent connections), but each spawn creates a
*fresh* session and never consults any store:

```rust
while let Some(incoming) = endpoint.accept().await {           // main.rs:149
    ...
    tokio::spawn(async move {
        let conn = match incoming.await { ... };
        ...
        if let Err(e) = run_session(conn, shell, scrollback).await { ... }   // main.rs:188
    });
}
```

`grep -rniE "detach|reattach|session.?store|resume|QuicTransportConfig|keep_alive|max_idle_timeout|transport_config"`
over `moshers2/crates` returns **nothing**. Confirmed: no detach machinery, no QUIC tuning.

### PROPOSED design for `moshers2` (since neither repo has it)

Goal: decouple the **long-lived `Session`** (PTY + `ServerTerminal`, which must keep draining
PTY output even with no client attached, so the screen stays current) from the
**per-connection `Transport<TerminalScreen, UserInput>`**. Reconnecting client re-attaches to
its existing `Session`; a *fresh* `Transport` re-syncs it to the current screen (see §3).

Key building blocks already present:
- `ServerTerminal` (`/Users/kisaczka/Desktop/code/moshers2/crates/terminal/src/server.rs`)
  owns the live `vt100::Parser` and produces `TerminalScreen` snapshots via
  `pub fn snapshot(&self) -> TerminalScreen`. It is the thing that must keep running.
- `rmosh_pty::Pty::spawn(rows, cols, shell, term) -> anyhow::Result<(Self, mpsc::Receiver<Vec<u8>>)>`
  (`/Users/kisaczka/Desktop/code/moshers2/crates/pty/src/lib.rs:35`). The `Receiver<Vec<u8>>`
  is the PTY output stream that must be drained continuously.
- `IrohChannel::remote_id() -> EndpointId`
  (`/Users/kisaczka/Desktop/code/moshers2/crates/transport-iroh/src/lib.rs:178`) — the natural
  store key (matches the allowlist model: server already authorizes by client `EndpointId`).

**Store key**: client `EndpointId` (one detachable session per authorized client). This is
the mosh-parity choice for a single-user server and needs no new id negotiation. (If you
later want multiple named sessions per client, add an explicit session-id sent in the
auth/handshake; for now keyed-by-peer is simplest and matches the allowlist.)

Sketch (new module `crates/server/src/session.rs`):

```rust
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use iroh::EndpointId;
use tokio::sync::{mpsc, Mutex};
use rmosh_pty::Pty;
use rmosh_terminal::ServerTerminal;

/// A long-lived shell session that outlives any single client connection.
/// Owns the PTY + emulator; a background task keeps draining PTY output into `emu`
/// whether or not a client is attached, so the screen is always current on reattach.
pub struct Session {
    pub emu: ServerTerminal,        // live vt100 parser + echo-ack
    pub pty: Pty,                   // for write_input / resize / kill
    pub pty_rx: mpsc::Receiver<Vec<u8>>, // PTY output (drained by the run loop while attached;
                                          // by a detached drain task while not)
    pub child_alive: bool,
    pub attached: bool,             // true while a connection owns the run loop
    pub last_detach: Option<Instant>, // when the last client left (for TTL reaping)
}

/// EndpointId -> shared Session. One mutex per session keeps the run loop's borrow simple.
pub type SessionStore = Arc<Mutex<HashMap<EndpointId, Arc<Mutex<Session>>>>>;
```

Lifecycle:

1. **Connect / attach**: on an authorized connection, look up `store[peer]`.
   - Miss -> `Pty::spawn(...)`, build `ServerTerminal`, insert a new `Session`, mark
     `attached = true`.
   - Hit -> reuse the existing `Session`; if a *detached drain task* was running, stop it
     (so the run loop owns `pty_rx`); set `attached = true`, `last_detach = None`.
2. **Run loop** (the body of today's `run_session`) drives a **fresh** `Transport` per
   connection over the `IrohChannel`, draining `pty_rx` into `emu` and applying client input.
3. **Detach** (peer close / connection error): do **not** kill the PTY. Set `attached =
   false`, `last_detach = Some(Instant::now())`, and spawn a *detached drain task* that keeps
   `emu.process(pty_rx.recv())` running so the screen stays current. Drop the `Transport`.
4. **Shell exit** (`pty_rx` returns `None` -> `child_alive = false`): finish the SSP shutdown
   handshake if a client is attached, then remove the session from the store.
5. **TTL / reaping**: a background sweeper removes sessions whose `last_detach` is older than
   `SESSION_TTL` (and kills their PTY). Mosh's `mosh-server` exits when the network peer is
   gone for too long; pick e.g. `SESSION_TTL = Duration::from_secs(7 * 24 * 3600)` or a config
   flag (`--session-ttl`). I have **not** found a corresponding value in either repo — this is
   a new policy choice.

Note on the detached drain task vs the run loop: only one owner may hold `pty_rx` at a time
(`mpsc::Receiver` is not clonable). Cleanest is to *not* spawn a separate drain task; instead
keep one **per-session supervisor task** that always owns `pty_rx` and `emu`, and have the
connection run loop talk to it. But that is a larger refactor. The minimal version is the
"hand `pty_rx` back and forth" approach above; document the invariant ("exactly one of {run
loop, drain task} owns `pty_rx`") and gate it behind the `attached` flag + the session mutex.

---

## 2. QUIC keepalive / idle timeout

### Does `moshers`/`moshers2` configure a `QuicTransportConfig`? — NO

Neither repo calls `transport_config`, `QuicTransportConfig`, `keep_alive_interval`, or
`max_idle_timeout`. Both rely entirely on iroh's preset defaults.

`moshers2` endpoint builders (`/Users/kisaczka/Desktop/code/moshers2/crates/transport-iroh/src/lib.rs`):

```rust
pub async fn bind_endpoint(secret: SecretKey, accept: bool) -> Result<Endpoint, SetupError> {
    let mut builder = Endpoint::builder(presets::N0).secret_key(secret);     // lib.rs:90
    if accept { builder = builder.alpns(vec![ALPN.to_vec()]); }
    let ep = builder.bind().await.map_err(|e| SetupError::Other(e.into()))?;
    Ok(ep)
}
```
`bind_endpoint_local` (`presets::Minimal`, lib.rs:104) and `bind_endpoint_with_relay`
(`presets::Minimal` + `.relay_mode(RelayMode::custom([relay]))`, lib.rs:147) are identical in
shape — **no `.transport_config(...)`**.

`moshers` is the same (`/Users/kisaczka/Desktop/code/moshers/crates/moshers-iroh/src/endpoint.rs:23`
`bind`): `Endpoint::builder(presets::N0).secret_key(secret)` with no transport config.

### IMPORTANT: iroh 1.0 already sets aggressive keepalive/idle defaults

This changes the framing of the problem. iroh 1.0's *default* `QuicTransportConfig` already
turns keepalive on and sets a short **per-path** idle timeout. From
`.../iroh-1.0.0/src/endpoint/quic.rs` (`QuicTransportConfigBuilder::new`):

```rust
fn new() -> Self {
    let mut cfg = noq::TransportConfig::default();
    // Override some transport config settings.
    cfg.keep_alive_interval(Some(HEARTBEAT_INTERVAL));
    cfg.default_path_keep_alive_interval(Some(HEARTBEAT_INTERVAL));
    cfg.default_path_max_idle_timeout(Some(PATH_MAX_IDLE_TIMEOUT));
    cfg.max_concurrent_multipath_paths(MAX_MULTIPATH_PATHS);
    cfg.max_remote_nat_traversal_addresses(MAX_QNT_ADDRESSES);
    cfg.server_handshake_migration(true);
    Self(cfg)
}
```

Constant values (`.../iroh-1.0.0/src/socket.rs`):

```rust
pub(crate) const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);    // socket.rs:109
pub(crate) const PATH_MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(15);// socket.rs:117
pub(crate) const MAX_MULTIPATH_PATHS: u32 = 8;                             // socket.rs:137
pub(crate) const MAX_QNT_ADDRESSES: u8 = 32;                              // socket.rs:145
```

So by default:
- Connection keepalive PINGs every **5s** (`keep_alive_interval`).
- Each **path** is dropped after **15s** of inactivity (`default_path_max_idle_timeout`),
  but iroh keeps the connection alive across paths (multipath up to 8 paths + relay
  fallback), and `server_handshake_migration(true)` allows the path to move.
- The **connection-level** `max_idle_timeout` is *not* overridden in `new()`, so it stays at
  `noq::TransportConfig::default()` (quinn's default is 30s; I did not independently re-verify
  noq's exact default value — treat "≈30s" as "noq default", not measured).

Hard constraint to know: the per-path knobs are **clamped**. `default_path_max_idle_timeout`
rejects anything above 15s, and `default_path_keep_alive_interval` ignores anything above 5s
(`quic.rs:490–520`):

```rust
/// Note: values higher than `PATH_MAX_IDLE_TIMEOUT` (15 seconds) are clamped and a warning is logged.
pub fn default_path_max_idle_timeout(mut self, timeout: Duration) -> Self { ... }
/// Note: this method will ignore values higher than the recommended 5 seconds and will log a warning.
pub fn default_path_keep_alive_interval(mut self, interval: Duration) -> Self { ... }
```

`max_idle_timeout` (the **connection** timeout) is *not* clamped to 15s and is the knob you
should raise to survive brief suspends. Its doc:

```rust
/// Maximum duration of inactivity to accept before timing out the connection.
/// The true idle timeout is the minimum of this and the peer's own max idle timeout. `None`
/// represents an infinite timeout. Defaults to 30 seconds.
pub fn max_idle_timeout(mut self, value: Option<IdleTimeout>) -> Self { ... }   // quic.rs:211
```

Conclusion for §2: tuning helps marginally (raise the **connection** `max_idle_timeout` to,
say, 60–120s so a laptop-lid-close of <2 min doesn't drop the connection; keepalive is
already 5s and you cannot make per-path idle exceed 15s). But because a single path dies at
15s and the connection idle timeout caps how long a fully-suspended client survives, **QUIC
tuning alone cannot give mosh-grade "suspend for an hour, reconnect" behaviour. The §1
detachable-session store is the real fix**; QUIC tuning just widens the window where the
*same* connection survives.

### Exact iroh 1.0.0 API to set transport config

Builder methods (full signatures, from `.../iroh-1.0.0/src/endpoint/quic.rs`):

```rust
impl QuicTransportConfig {
    pub fn builder() -> QuicTransportConfigBuilder { ... }          // quic.rs:134
}
impl QuicTransportConfigBuilder {
    pub fn build(self) -> QuicTransportConfig { ... }               // quic.rs:166
    pub fn keep_alive_interval(mut self, value: Duration) -> Self { ... }       // quic.rs:365  (bare Duration, NOT Option)
    pub fn max_idle_timeout(mut self, value: Option<IdleTimeout>) -> Self { ... } // quic.rs:211
}
```

Endpoint builder method (from `.../iroh-1.0.0/src/endpoint.rs:669`):

```rust
pub fn transport_config(mut self, transport_config: QuicTransportConfig) -> Self { ... }
```

Both `QuicTransportConfig`, `QuicTransportConfigBuilder`, and `IdleTimeout` are re-exported
from `iroh::endpoint` (`.../iroh-1.0.0/src/endpoint.rs:107,109` re-exports them from the
`quic` module). `IdleTimeout: TryFrom<Duration>` (errors as `VarIntBoundsExceeded`) and also
`From<VarInt>`. From the doc example on `max_idle_timeout`:

```rust
use std::{convert::TryInto, time::Duration};
use iroh::endpoint::{QuicTransportConfig, VarInt, VarIntBoundsExceeded};
let mut builder = QuicTransportConfig::builder()
    .max_idle_timeout(Some(VarInt::from_u32(10_000).into()));        // VarInt-encoded ms
builder = builder.max_idle_timeout(Some(Duration::from_secs(10).try_into()?)); // or a Duration
let _cfg = builder.build();
```

Minimal usage that compiles against iroh 1.0.0 (the value to set in `moshers2`):

```rust
use std::time::Duration;
use iroh::endpoint::{presets, IdleTimeout, QuicTransportConfig};

let tc = QuicTransportConfig::builder()
    .keep_alive_interval(Duration::from_secs(5))                          // PING every 5s (== default)
    .max_idle_timeout(Some(IdleTimeout::try_from(Duration::from_secs(60)).unwrap()))
    .build();

let endpoint = iroh::Endpoint::builder(presets::N0)
    .secret_key(secret)
    .transport_config(tc)
    // .alpns(vec![ALPN.to_vec()])  // server side
    .bind()
    .await?;
```

Caveat: `.transport_config(tc)` *replaces* the whole config object, so you lose iroh's
defaults for the other fields it set in `new()` UNLESS you start from
`QuicTransportConfig::builder()` (which itself starts from those defaults — verified in
`new()` above). So always build via `QuicTransportConfig::builder()...` (do **not** build a
raw `noq::TransportConfig`), and you keep multipath/NAT-traversal/handshake-migration defaults
while overriding only keepalive + idle.

### Map onto `moshers2` `transport-iroh` (today's signatures)

Today (all in `/Users/kisaczka/Desktop/code/moshers2/crates/transport-iroh/src/lib.rs`):
```rust
pub async fn bind_endpoint(secret: SecretKey, accept: bool) -> Result<Endpoint, SetupError>           // :89
pub async fn bind_endpoint_local(secret: SecretKey, accept: bool) -> Result<Endpoint, SetupError>     // :103
pub async fn bind_endpoint_with_relay(secret: SecretKey, accept: bool, relay: RelayUrl) -> Result<Endpoint, SetupError> // :142
```

Proposed: add a private helper that builds the transport config once, and apply it in all
three. Keep public signatures unchanged (callers in `server/main.rs` and `client/main.rs`
keep compiling):

```rust
use iroh::endpoint::{presets, IdleTimeout, QuicTransportConfig};

/// Keepalive + idle-timeout tuned so a brief client suspend doesn't drop the connection.
/// (iroh defaults: keepalive 5s, per-path idle 15s, conn idle ~30s. We raise conn idle.)
fn rmosh_transport_config() -> QuicTransportConfig {
    QuicTransportConfig::builder()
        .keep_alive_interval(std::time::Duration::from_secs(5))
        .max_idle_timeout(Some(
            IdleTimeout::try_from(std::time::Duration::from_secs(60))
                .expect("60s fits in IdleTimeout"),
        ))
        .build()
}

pub async fn bind_endpoint(secret: SecretKey, accept: bool) -> Result<Endpoint, SetupError> {
    let mut builder = Endpoint::builder(presets::N0)
        .secret_key(secret)
        .transport_config(rmosh_transport_config());   // <-- new line
    if accept { builder = builder.alpns(vec![ALPN.to_vec()]); }
    let ep = builder.bind().await.map_err(|e| SetupError::Other(e.into()))?;
    Ok(ep)
}
// identical added line in bind_endpoint_local (presets::Minimal) and
// bind_endpoint_with_relay (presets::Minimal + .relay_mode(...))
```

Unverified value choice: 60s is a guess balancing "survive a short suspend" vs "don't pin a
dead session forever". Pair it with the §1 store TTL for longer suspends. I did not find an
existing target value in either repo.

---

## 3. Re-seeding a fresh `Transport` on reattach so the client re-syncs to the CURRENT screen

**Yes, this works, and it is automatic.** A brand-new `Transport<TerminalScreen, UserInput>`
starts from a *default* base state (num 0). On the first `tick`, its diff is computed against
that default base, so it emits the **full current screen** as one (large, fragmented) update.

How `Transport::new` seeds the base (from
`/Users/kisaczka/Desktop/code/moshers2/crates/ssp/src/transport.rs:85`):

```rust
pub fn new(now: u64, mtu: usize) -> Self {
    let mut sent_states = VecDeque::new();
    sent_states.push_back(TimestampedState {
        timestamp: now,
        num: 0,        // base state num 0
        ...            // state: Local::default()  (a default TerminalScreen)
    });
    ...
}
```

`TerminalScreen::default()` is a blank 24x80 screen
(`/Users/kisaczka/Desktop/code/moshers2/crates/terminal/src/lib.rs:83`). When the run loop
sets `*transport.current_mut() = emu.snapshot();` and ticks, the SSP diffs
`current (= live screen)` against the base (`default`). That diff goes through
`TerminalScreen::diff_from` (`terminal/src/lib.rs:146`):

```rust
fn diff_from(&self, base: &Self) -> Self::Diff {
    let resized = self.size() != base.size();
    let vt = if resized {
        self.screen.state_formatted()         // self-contained full repaint
    } else {
        self.screen.state_diff(&base.screen)  // incremental
    };
    ScreenDiff { resize: resized.then(|| self.size()), echo_ack: self.echo_ack,
                 title: (self.title != base.title).then(|| self.title.clone()), vt }
}
```

Two cases on reattach, both correct:
- **Same geometry as default (24x80):** `resized == false`, so `vt = state_diff(&blank)`.
  `vt100::Screen::state_diff` against a blank screen yields the escape sequences to paint the
  whole current screen (it diffs every non-default cell vs blank) — i.e. effectively a full
  repaint. The client's `apply` builds a throwaway parser and replays it (lib.rs:162). Result:
  client converges to the current screen.
- **Different geometry (the live session was resized away from 24x80):** `resized == true`,
  so `vt = state_formatted()` — an explicit self-contained full repaint plus `resize`. The
  client's `apply` rebuilds its parser at the new size and replays. Result: client converges,
  including the resize.

So a fresh `Transport` re-seeded with `emu.snapshot()` always re-syncs the reconnecting
client to the **current** screen — no extra "full snapshot" code path is needed; the existing
`diff_from`/`apply` already handle "diff against default base" as the full-screen case.
(Confirmed in spirit by `terminal/src/lib.rs` test `diff_apply_roundtrip_simple`, which diffs
a populated screen against `TerminalScreen::default()` and round-trips.)

One thing to set explicitly on reattach: the new `Transport`'s `current` must be the live
snapshot *before* the first tick, exactly as `run_session` already does
(`/Users/kisaczka/Desktop/code/moshers2/crates/server/src/lib.rs:33`):

```rust
*transport.current_mut() = emu.snapshot();
```

Caveat I could **not** fully verify from source: whether `vt100::Screen::state_diff(&blank)`
restores **scrollback** and **all** modes identically to `state_formatted()`. The resize
branch already prefers `state_formatted()` for correctness. To be safe on reattach you may
want to *force* the full-repaint path regardless of geometry. Cheapest way without touching
`ssp`: seed the new `Transport` and, before the first tick, make the base differ in size from
the live snapshot is hacky. Cleaner: add a `Transport::reseed_full(&mut self, state)` or a
`SyncState::diff_full()` so reattach always ships `state_formatted()`. If you trust
`state_diff(&blank) == full repaint` for your `vt100` version, no change is needed. **Verify
this against the `vt100` crate version in `Cargo.lock` before relying on the cheap path.**

---

## Concrete refactor plan (function shapes)

### A. `crates/transport-iroh/src/lib.rs`
- Add `fn rmosh_transport_config() -> QuicTransportConfig` (see §2).
- Add `.transport_config(rmosh_transport_config())` to the builder in all three
  `bind_endpoint*` fns. Public signatures unchanged.
- (Client `connect` path: per-connection transport config can also be set via
  `ConnectOptions::new().with_transport_config(cfg)` — seen in
  `.../iroh-1.0.0/src/address_lookup.rs:1108` — but setting it once on the endpoint builder is
  simpler and applies to both accept and connect.)

### B. `crates/server/src/session.rs` (new)
```rust
pub struct Session { /* emu, pty, pty_rx, child_alive, attached, last_detach */ }
pub type SessionStore = Arc<Mutex<HashMap<EndpointId, Arc<Mutex<Session>>>>>;

/// Get-or-create the session for `peer`; marks it attached and stops any detached drain task.
pub async fn attach(store: &SessionStore, peer: EndpointId,
                    shell: Option<&str>, scrollback: usize) -> anyhow::Result<Arc<Mutex<Session>>>;

/// Mark `peer`'s session detached (records last_detach) and start a drain task that keeps
/// emu current from pty_rx. Does NOT kill the PTY.
pub async fn detach(store: &SessionStore, peer: EndpointId);

/// Remove + kill a session (shell exited, or TTL reaper).
pub async fn reap(store: &SessionStore, peer: EndpointId);

/// Background task: periodically reap sessions whose last_detach > ttl.
pub async fn run_reaper(store: SessionStore, ttl: Duration);
```

### C. `crates/server/src/lib.rs` (`run_session` -> split)
Change `run_session` to take the shared `Session` instead of spawning its own PTY:

```rust
pub async fn run_session(
    conn: iroh::endpoint::Connection,
    session: Arc<Mutex<Session>>,   // was: shell: Option<String>, scrollback: usize
) -> anyhow::Result<()> {
    let channel = IrohChannel::new(conn);
    let clock = MonoClock::new();
    // FRESH transport each attach -> first tick re-syncs full screen (see §3).
    let mut transport =
        Transport::<TerminalScreen, UserInput>::new(clock.now_ms(), channel.max_datagram_size());
    transport.set_connected(true);

    let mut s = session.lock().await;            // hold emu+pty+pty_rx for the loop
    *transport.current_mut() = s.emu.snapshot(); // re-seed to current screen
    // ... existing select! loop, but use s.emu / s.pty / s.pty_rx, s.child_alive ...
    // On `channel.recv()` Err  -> break WITHOUT killing pty (detach).
    // On pty_rx None           -> s.child_alive = false; start_shutdown; eventually reap.
    // Drop the Transport on return; do NOT call s.pty.kill() on plain disconnect.
}
```
Key behavioural deltas vs today's `lib.rs:106-123`:
- The `channel.recv()` Err arm (lib.rs:89) -> `break` but **no** `pty.kill()`.
- The end-of-fn `let _ = pty.kill();` (lib.rs:122) moves to `reap`/shell-exit only.
- Everything else (mtu/rtt updates, `get_remote_diff`, `WireEvent::Keys`/`Resize`,
  `register_input_frame`, echo-ack, `tick`, shutdown handshake) is unchanged.

### D. `crates/server/src/main.rs` (accept loop)
```rust
let store: SessionStore = Default::default();
tokio::spawn(session::run_reaper(store.clone(), Duration::from_secs(/* ttl */)));

while let Some(incoming) = endpoint.accept().await {
    let store = store.clone();
    let shell = shell.clone();
    tokio::spawn(async move {
        let conn = incoming.await?;            // (existing handshake/allowlist/passphrase first)
        let peer = conn.remote_id();
        // ... allowlist + passphrase as today (main.rs:161-186) ...
        let session = session::attach(&store, peer, shell.as_deref(), scrollback).await?;
        if let Err(e) = run_session(conn, session).await { error!(?e, "session loop"); }
        session::detach(&store, peer).await;   // keep shell alive for reattach
    });
}
```

### Open questions / unverified items (flagged honestly)
1. `vt100::Screen::state_diff(&blank)` == full repaint incl. scrollback/modes? Verify against
   the `vt100` version in `moshers2/Cargo.lock`, or force `state_formatted()` on reattach (§3).
2. Exact noq connection-level `max_idle_timeout` default ("≈30s" is quinn's documented
   default and the iroh doc string says "Defaults to 30 seconds"; I did not byte-trace noq).
3. TTL value and the 60s `max_idle_timeout` value are policy choices with no precedent in
   either repo — pick deliberately / make them flags.
4. `mpsc::Receiver` single-owner constraint: the "hand pty_rx between run loop and drain task"
   approach needs a clear invariant; a per-session supervisor task that always owns
   `pty_rx`+`emu` is more robust but a bigger change.
