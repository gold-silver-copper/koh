# Changelog

All notable changes to koh are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and koh aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) for the **binary's CLI, the on-disk
`koh-key-v1` key format, and the wire `PROTOCOL_VERSION`/ALPN**. From 0.10.0 the library's config
types and entry points (`ServeConfig`/`serve`, `ConnectConfig`/`connect`, `IdConfig`/`run_id`,
`KeyConfig`/`keycmd::run`, and the `ssp` core) are covered too; everything else in the library is
internal and unstable (see `src/lib.rs`).

> **A note on versions.** [crates.io](https://crates.io/crates/koh) is the source of truth for what
> was actually released. Two git-tag-only gaps exist from koh's early, fast-moving security-review
> period: **v0.4.0–v0.4.3** were tagged during a rapid follow-up series but superseded by **0.4.4**
> before publishing, and **v0.6.0** (encrypted-at-rest keys, vt100 containment, per-node-id authz) was
> developed and folded into **0.7.0** rather than released on its own. Published versions:
> 0.1.0–0.3.2, 0.4.4, 0.5.0, 0.7.0–0.9.1.

## [0.12.0] — 2026-09-03

### Added
- Public cancellation-aware terminal input and resize producers for embedded clients.
- A documented `Pty::process_id` accessor for lifecycle coordination by generic hosts.

### Fixed
- Embedded client teardown now cancels producers blocked by full input or resize channels.

## [0.11.0] — 2026-09-03

### Changed
- **The server hosts any `SyncState` producer, not only a PTY** (KH-01). `session::Session`,
  `SessionHandle`, `SessionStore`, `attach_with`, `detach`, `reap`, `run_reaper`, `ServerSession`,
  `run_attached` (now also taking a `ClientId`) and `run_session_with` are generic over a
  `SessionHost`; `PtyHost` is the previous PTY + emulator code behind that trait. The echo-ack
  debounce moved out of `ServerTerminal` into the per-connection loop (KS-02): a host only
  implements `stamp_echo_ack`, and `ServerTerminal::snapshot` leaves `echo_ack` at 0 for the loop
  to stamp (`TerminalScreen::set_echo_ack`). `SessionHandle::changed` is a `ChangeSignal` (a `watch`
  version counter) rather than a `Notify`, so one pulse wakes every attached viewer (KS-03);
  `SessionHost::attach_notify` receives it. The K-16 unwind guard releases a connection's attach through
  its `HostProvider`, so a shared host is never pinned by a panicking connection task (KS-04). `serve` is
  unchanged in behaviour and is `serve_with(config, Hosts::new().with(TERMINAL_ALPN, PtyHosts))`
  underneath. `serve` installs its tracing subscriber with `try_init`, so an embedding binary that
  already owns one no longer panics.
- **The client renders any `ClientState`** (KC-01). `ClientSession<S>`, `run_client`,
  `ClientTerminal<S>::render(state, overlay, status)` (the window state now comes from
  `ClientState::window`), and the input-mode mirroring go through `client::InputModes` (byte-identical
  to vt100's sequences). `connect` is unchanged and is `connect_with(config, TERMINAL_ALPN, …)`.
- **`predict` reads screens through `predict::ScreenView`** instead of `&vt100::Screen` directly
  (implemented for `vt100::Screen`; still no `crate::` imports).
- `ssp::NEVER`, `ssp::testkit` and `Transport::current` are public (the latter two `#[doc(hidden)]`).

### Added
- **`SessionHost`, `HostProvider`, `PtyHosts`, `SharedHost`, `serve_with`, `cli::Hosts`,
  `ClientId`** — the server seam, including shared sessions (KS-01): every authorized peer attaches
  to one host with its own connection loop and `ClientId`; the reaper collects it only once every
  viewer has left.
- **`ClientState`, `ClientTerminal<S>`, `connect_with`, `run_client_with`, `InputModes`** — the
  client seam.
- **The synced state type is selected by ALPN** (KH-02): `transport_iroh::TERMINAL_ALPN`
  (`koh/iroh/1`, the existing ALPN) for `TerminalScreen`; `bind_endpoint*_alpns` bind several;
  `IrohConnector::with_alpn` dials one. A client dialing an ALPN the server does not bind fails the
  TLS handshake before any SSP bytes flow, with an error naming the ALPN.
- **`ServerTerminal::progress()` and `take_unhandled_oscs()`** (KO-01): OSC 9;4 progress reports
  and a bounded ring (16 × 256 bytes) of unhandled OSC payloads, host-side only.
- **`--on-bell <CMD>` / `ConnectConfig::bell_command` / `client::BellHook`** (KB-01): run a shell
  command when the remote bell rings; detached, `KOH_*`-scrubbed except `KOH_BELL_COUNT` and
  `KOH_TITLE`, at most one spawn per second. Bells from before the attach do not fire it; bells
  during a reconnect do (KB-02).
- Test infrastructure: `ssp::testkit::GridState`, `sim::run_generic_session`, three new
  integration targets (`e2e_generic_host`, `shared_session`, `bell_hook`), a `server_process`
  fuzz target, and a KS-01 proptest over shared-session refcounting.

### Unchanged
- Wire protocol, `PROTOCOL_VERSION` (3), the terminal ALPN, `TerminalScreen`/`ScreenDiff` on the
  wire, the `koh-key-v1` key format, and every CLI flag and default. `cargo install koh` builds
  the same binary behaviour, plus `--on-bell`.

## [0.10.0] — 2026-09-03

### Changed
- **License: MIT** (was GPL-3.0-or-later). Releases before 0.10.0 remain available under their
  original license. Motivation: koh is now consumed as a library by an MIT-licensed downstream
  (`fux`), and a GPL library would force that crate's license.
- **`cli` Cargo feature (on by default) now owns clap.** The `koh` binary, the `*Args` clap adapter
  structs, the `chaos` example and the pty-binary e2e test are gated on it. `cargo install koh` is
  unchanged; library users build with `default-features = false` plus one `backend-*` feature and
  get a clap-free tree.
- **Plain config types are the stable library surface.** `serve`, `connect`, `run_id` and
  `keycmd::run` take `impl Into<…Config>`: `ServeConfig`, `ConnectConfig`, `IdConfig`, `KeyConfig`
  (all public fields; `From<…Args>` under `cli`). Their `Default`/`new` match the CLI defaults,
  and `serve` re-checks the ranges clap used to enforce so a library caller gets the same errors.
- `session::spawn_session`, `session::attach`, `server::run_session` and `pty::Pty::spawn` take
  the hosted program as an argv slice (`&[String]`) instead of `Option<&str>`; empty still means
  the login shell.

### Added
- **`ServeConfig::command`: host any program, with arguments.** `command[0]` is the program and the
  rest its argv, passed verbatim — no whitespace splitting, so a path with a space still works. On
  the CLI, `--shell` may now be repeated to build the argv (`--shell zellij --shell attach --shell
  -c --shell main`); a single `--shell` behaves exactly as before.

### Unchanged
- Wire protocol, `PROTOCOL_VERSION`/ALPN, the `koh-key-v1` key format, and every CLI flag and
  default.

### Added (carried from the unreleased 0.9.x line)
- **Pluggable terminal backends for the client renderer** (`client::backend::KohBackend`), so an
  alternate terminal crate can drive `koh connect` without touching the protocol, prediction, or
  session code. The render path now speaks only to the backend trait — its default methods emit the
  same standard ANSI/DEC koh always did (byte-for-byte with the previous `termina` output), so a
  backend only has to wire up raw-mode + size. The backend is chosen at build time by cargo feature:
  `backend-termina` (default — `cargo install koh` is unchanged), `backend-crossterm`, or
  `backend-qwertty` (e.g. `--no-default-features --features backend-crossterm`). The out-of-band mode ledger
  (forwarded-mode reset on drop/suspend) and the OSC-52 clipboard opt-in stay backend-independent, so
  every backend restores the terminal identically. Implements
  [#11](https://github.com/gold-silver-copper/koh/issues/11).

## [0.9.1] — 2026-06-29

### Changed
- Shortened the README into a concise install/usage + highlights landing page.

## [0.9.0] — 2026-06-25

### Changed
- **Local-echo prediction is always on.** Keystrokes now always render speculatively; the engine's
  epoch gate still suppresses the echo at non-echoing (password) prompts, and high-RTT links still
  underline-flag unconfirmed predictions. Previously the shipped default (`adaptive`) hid predictions
  entirely on low-latency links.
- **The "link down — resuming…" banner no longer flashes on a single lost keepalive.** Its grace
  was 3 s — exactly the keepalive interval — so one dropped or jittered keepalive on a lossy link
  briefly tripped it. The grace is now three keepalive intervals (~9 s), so transient packet loss is
  absorbed and the banner only appears on a genuine stall (`Ctrl-^ .` still quits immediately).

### Removed
- **`koh connect --predict <always|never|adaptive>`** — there is no prediction toggle; prediction is
  unconditionally on (see above).

## [0.8.0] — 2026-06-25

A large security/minimalism + release-maturity pass. **Breaking** (flags, env vars, and the default
key location changed).

### Removed
- **`--allow-any`** — there is no "accept any peer" mode; at least one `--allow <id>` is required, so a
  stray `koh serve` can never publish an open shell.
- **`--read-only`** — the observer mode is gone; the node-id allowlist is the sole access control.
- **`--allow-file` / per-peer authorization** and three low-value config knobs; the clipboard handling
  was consolidated.
- **`$KOH_STATE_DIR`** and the `directories` dependency.

### Changed
- **All koh-owned files now live under `~/.config/koh` only** (`$XDG_CONFIG_HOME/koh` is honored).
  Removed the platform-specific dir (macOS *Application Support*) and every `/tmp` / `/data/local/tmp`
  / CWD fallback; koh now errors rather than scattering a key when `~/.config` can't be located
  (`--key-file` remains the explicit override).
- **Identity-key hardening:** passphrase floor raised from 8 to **12 characters**, and Argon2id
  `t_cost` 3 → 4 (both apply to newly-written keys only; existing keys still decrypt).
- **Stricter builds:** `overflow-checks = true` in release, `dead_code = "deny"`.

### Added
- Property tests for the attacker-reachable parsers (`Transport::recv`, `FragmentAssembly::add`,
  `decrypt_key`); the terminal parser rebuild now runs through the vt100 panic-containment path.
- Release/maturity tooling: a `COPYING` (GPL-3.0) license file, this changelog, and CI that verifies
  the MSRV, builds on macOS, and treats clippy warnings as errors.

### Fixed
- Idle empty-ack flood (an idle side re-sent an empty ack every ~100 ms instead of settling onto the
  3 s keepalive); the prediction engine now resets its byte decoder on resize; redundant server-side
  re-snapshots on the input path.

## [0.7.0] — 2026-06-25
- **Removed the SPAKE2/PAKE passphrase second factor.** Identity keys are now **always encrypted at
  rest** (`koh-key-v1`: Argon2id + AES-256-GCM), and authorization is the node-id allowlist alone. Also
  ships the prior 0.6.0 work: vt100 panic containment on both sides and per-node-id authorization.

## [0.5.0] — 2026-06-24
- Architectural review follow-ups: a pure, I/O-free `ServerSession` core; required per-state DoS bounds
  (`RECV_DECODE_LIMIT` / `RECEIVE_BUDGET_UNITS`); RAII attach guards; a CI layering guard.

## [0.4.4] — 2026-06-24
- Engineering-quality pass: fuzz targets + property tests on the untrusted decoders, an idle-snapshot
  gate, CI + `cargo-deny`, and docs. Supersedes the unpublished 0.4.0–0.4.3 interim security fixes.

## [0.3.2] — 2026-06-23
- Security-audit hardening of the post-auth data plane (inflation / reassembly / accumulation caps) and
  a screen-off reconnect fix.

## [0.3.1] — 2026-06-23
- Hardening against hostile or compromised peers (transport-level fixes).

## [0.3.0] — 2026-06-23
- Detachable/reattachable sessions, terminal-reply synthesis (DSR/DA/DECRQM), remote exit-status
  propagation, and the opt-in Android-emulator test suite.

## [0.2.0] — 2026-06-23
- Early iteration of the transport + terminal core.

## [0.1.0] — 2026-06-23
- Initial release: the SSP protocol core, the terminal model, the PTY host, the local-echo predictor,
  and the iroh QUIC transport.

[Unreleased]: https://github.com/gold-silver-copper/koh/compare/v0.9.1...HEAD
[0.9.1]: https://github.com/gold-silver-copper/koh/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/gold-silver-copper/koh/releases/tag/v0.9.0
[0.8.0]: https://github.com/gold-silver-copper/koh/releases/tag/v0.8.0
[0.7.0]: https://github.com/gold-silver-copper/koh/releases/tag/v0.7.0
[0.5.0]: https://github.com/gold-silver-copper/koh/releases/tag/v0.5.0
[0.4.4]: https://github.com/gold-silver-copper/koh/releases/tag/v0.4.4
[0.3.2]: https://github.com/gold-silver-copper/koh/releases/tag/v0.3.2
[0.3.1]: https://github.com/gold-silver-copper/koh/releases/tag/v0.3.1
[0.3.0]: https://github.com/gold-silver-copper/koh/releases/tag/v0.3.0
[0.2.0]: https://github.com/gold-silver-copper/koh/releases/tag/v0.2.0
[0.1.0]: https://github.com/gold-silver-copper/koh/releases/tag/v0.1.0
