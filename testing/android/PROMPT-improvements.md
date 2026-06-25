# TASK: Fix the Android robustness issues the emulator tests surfaced, and add the high-value emulator tests

> **NOTE (historical brief; auth model changed in 0.7.0).** Any passphrase / PAKE / second-factor or
> `--allow-any` references below predate 0.7.0 and no longer match koh: the PAKE factor was removed,
> servers require `--allow <id>`, and identity keys are always encrypted under `$KOH_KEY_PASSPHRASE`.
> The live `scripts/` are the source of truth; this file is kept as history.

## GOAL
Land four code fixes that the Android emulator tests revealed as real koh gaps, and add five new
emulator tests that exercise koh's marquee Android behaviors. Keep every existing gate green.

## CONTEXT
You are working in the `koh` repo (`/Users/kisaczka/Desktop/code/moshers2`). `koh` is a single-crate
Rust CLI: **mosh reimplemented over iroh p2p QUIC**, explicitly aimed at Android/Termux and an
eventual Bevy-based Android terminal app. Host is Apple Silicon macOS; an arm64-v8a Android emulator
+ NDK are already set up (see `testing/android/README.md`). The opt-in emulator harness lives in
`testing/android/scripts/` — read `lib.sh` and `stress-lib.sh` first; reuse their helpers, don't
reinvent them.

These changes came out of running the emulator/stress suites against a real device. The harness
already proved the **good** news (no leaks, bounded memory, graceful drain, link-drop resilience,
the DNS-panic fix holds). This task addresses what it found **wrong** or **untested**.

## HARD CONSTRAINTS (read first)
- **`unsafe_code = "forbid"`** crate-wide; clippy denies the panic family (`unwrap_used` /
  `expect_used` / `panic` / `indexing_slicing` / `string_slice`) and runs pedantic+nursery. Justify
  any infallible site with `#[expect(clippy::…, reason = "…")]`. Never add an `unwrap`/`expect`/
  `panic`/index on peer-influenced input.
- **All six green gates must pass** after every change:
  `cargo fmt --check` · `cargo clippy --all-targets` · `cargo clippy --target aarch64-linux-android`
  · `cargo test` (currently 121 unit + integration) · `cargo run --example chaos -- chaos --loss 0.5`
  (must print `CONVERGED`) · `cargo build --locked`.
- New code gets **in-process unit tests** (the emulator tests are a separate, opt-in layer — they are
  NOT a substitute for unit coverage).
- Emulator tests stay **opt-in** (`KOH_ANDROID_EMULATOR=1`), **CI-safe** (clean SKIP / exit 0 with no
  device), **idempotent**, headless, and **never** part of default `cargo test` (the Rust gate is
  `#[ignore]`d). Add new stress scripts to `testing/android/scripts/` and register them in
  `run-stress.sh`; update `testing/android/README.md` + `.env.example`.
- Commit logically (a `fix:`/`feat:` per concern, then a `test:` for the emulator additions),
  matching the repo's trunk-based, conventional-commit style. Do not commit/push unless asked.

---

# PART A — Code fixes

## A1. Android-aware default session shell  (`src/pty.rs`)
**Problem.** `Pty::spawn(None, …)` calls `CommandBuilder::new_default_prog()` (portable-pty), which
resolves `$SHELL` else **`/bin/sh`** — a path that does not exist on Android (it's `/system/bin/sh`).
On bare Android (`adb shell`, no `$SHELL`) the session shell fails to spawn; every stress test had to
pass `--shell /system/bin/sh`. The Bevy app (no `$SHELL`) will hit this too.

**Fix.** In `src/pty.rs` (the `None =>` arm around line 92-94), when no shell is given, resolve in
order: `$SHELL` (if set and non-empty) → on `cfg!(target_os = "android")` a working Android shell
(`/system/bin/sh`) → `/bin/sh`. Build the `CommandBuilder` from that path rather than the bare
`new_default_prog()` default. Factor the resolution into a small pure helper
`fn default_shell() -> String` (or `OsString`) so it is unit-testable.

**Unit test.** Cover `default_shell()`: with `SHELL` set it returns that; unset, it returns a
non-empty path; and on Android the path is one that exists on a device. (Test the helper directly;
don't shell out.) Keep it deterministic (drive via an injected env lookup, not the process env, if
that's cleaner under the no-panic lints).

## A2. Robust default key path on Android  (`src/client/cli.rs`, `src/server/cli.rs`)
**Problem.** Both `default_key_file()` use `directories::ProjectDirs::from("","","koh")`, which on
Android yields **no** stable dir → falls back to a **relative** `koh-{server,client}.key` in the CWD.
Via `adb shell` the CWD is read-only `/`, so key creation fails (tests had to pass `--key-file`); and
generally it scatters keys wherever you happen to `cd`.

**Fix.** Make the fallback deterministic and writable on Android:
- Prefer `ProjectDirs` when it yields a path (desktop unchanged).
- Else, on Android, resolve a writable base in order: `$KOH_STATE_DIR` → `$HOME/.config/koh` (Termux
  sets `$HOME`) → `$TMPDIR` → `/data/local/tmp/koh`. Use a stable absolute path, not the CWD.
- When the chosen key path's parent isn't creatable/writable, surface a **clear error** (the binary
  already `?`-propagates from `load_or_create_secret_key`; make sure the message names the path and
  suggests `--key-file`). Do not silently write to CWD.
- Factor the resolution into a shared helper so client and server agree (e.g. a
  `transport_iroh`-level `default_key_path(role: &str) -> PathBuf`), and unit-test it with injected
  env (no `$HOME` → Android fallback; `$KOH_STATE_DIR` honored; desktop `ProjectDirs` path used).

## A3. Honest auth verdict  (`src/transport_iroh/auth.rs`)
**Problem.** The client prints `connected.` *before* the server validates the passphrase:
`handshake_client` writes its challenge response and returns `Ok` **without** reading a verdict, so a
**wrong passphrase still prints `connected.`**, then the server silently closes the connection. The
user sees "connected" then a confusing drop (and it made the auth stress test impossible to assert on
client output).

**Fix.** Add an explicit 1-byte verdict to the passphrase path of the handshake:
- `handshake_server` (the `Some(pass)` arm): after `recv.read_exact(&mut resp)` and computing
  `expect`, **write a 1-byte verdict** (`1` = accept, `0` = reject) on `send` *before* `send.finish()`,
  then return `Err(ChallengeFailed)` on mismatch as today.
- `handshake_client` (the `tag == PASS_REQUIRED` arm): after `send.write_all(&resp)` + `send.finish()`,
  **read the 1-byte verdict** from `recv`; if it's reject, return `Err(AuthError::ChallengeFailed)`.
- The `NO_PASS` path is unchanged (no challenge → implicit accept).
- Stream ordering (no deadlock): server sends `[PASS_REQUIRED, nonce]`, reads `resp`, writes
  `verdict`, finishes; client reads `tag`+`nonce`, writes `resp`+finishes its send, reads `verdict`.
- **Compatibility note:** this changes the *passphrase handshake* wire format (a new-client read vs an
  old-server that doesn't send the byte would fail). This is the koh-specific auth handshake, NOT the
  SSP `PROTOCOL_VERSION` (3, in `wire.rs`, which gates the post-handshake stream — leave it unless you
  also change the SSP). Both peers already must run matching koh versions; bump the crate version and
  note the break in the commit. Keep `constant_time_eq` comparison + the `Zeroizing`/`SecretString`
  hygiene intact.

**Unit test.** Extend the `auth.rs` tests: a correct passphrase yields accept and a wrong one yields
`ChallengeFailed` **observed on the client side** via the verdict (today only the server detects it).

## A4. Document the `--direct` reconnect limitation  (`README.md`)
**Problem.** On a `--direct <ip:port>` connection, transparent reconnect re-dials the *same* address;
if the server restarts on a new ephemeral port, the client can't re-establish (it works fine on the
normal relay/node-id path). The emulator reconnect test verified "rides out the drop / stays alive"
but could not verify full re-establishment on loopback for exactly this reason.

**Fix.** Add a one/two-line caveat to the Android/reconnect section of `README.md`: `--direct`
reconnect can't survive a server **port** change (use a fixed port or the relay/discovery path for
durable reconnection). Docs only — no code.

---

# PART B — New emulator tests

Add these under `testing/android/scripts/`, reusing `stress-lib.sh` (`start_server`, `server_pid`,
`koh_pids`, `rss_kb`, `pty_connect_host_bg`, `push_flood_script`, `cat_dev`, `wait_file_contains`,
`connect_once`, `finish`, `ok`/`bad`). Honor `KOH_STRESS_LEVEL` and add a per-test count/duration
knob. **Read the "Notes on the harness" in `README.md` first** — they encode hard-won facts (assert
on the server log / `/proc`, not client output; drive floods server-side via `--shell <script>`;
distinct keys for distinct registrations; PTY capture via adb's *local* stdout). Register every new
script in `run-stress.sh` and document it in the README table + `.env.example`.

## B1. Client freeze → resume  (the real screen-off scenario) — `stress-client-freeze.sh`
A live PTY session; `SIGSTOP` the **client** (a phone screen-off freezes the app, stopping its
keepalives), wait, `SIGCONT`. This is the scenario koh's 300s idle timeout exists for: the session
must ride out the freeze on the **same** connection (no reconnect).
- `start_server ""`; capture `SPID = server_pid` (only the server runs yet).
- `pty_connect_host_bg` a client (long hold). Wait for attach; compute `CLIENT_PID` = the koh pid
  that isn't `SPID`.
- `kill -STOP $CLIENT_PID`; assert `/proc/$CLIENT_PID/stat` field 3 is `T` (stopped). Hold ~15s
  (well under the 300s idle timeout).
- `kill -CONT $CLIENT_PID`; sleep a few seconds.
- **Assert (FATAL):** the client is still alive; it stayed on the **same** connection — the server
  log shows **no** "client detached" / "reattaching" between attach and now (it was NOT a reconnect);
  no panic on either side.

## B2. Detachable-session reattach continuity  (the "close the lid, reopen" feature) — `stress-reattach-continuity.sh`
Prove that disconnect→reconnect lands back in the **same** session with the **same** shell process,
not a fresh one.
- `push_flood_script` a session shell that records each *spawn* then stays interactive, e.g.
  body: `echo spawned >> /data/local/tmp/koh-spawns ; exec /system/bin/sh`. Reset the spawns file.
- `start_server "--shell <that script>"` (default 24h TTL; keep it alive throughout).
- Client **A** connects (PTY, same key both times), reaches `connected.`, then quits (`Ctrl-^ .`).
  Server log must show "client detached (session retained)".
- Reconnect client **A** (same key) → server reattaches.
- **Assert (FATAL):** the spawns file has **exactly one** line (the shell was spawned once and
  *reused*, not respawned); the server log shows exactly one "started a new session" and a
  "reattaching to this peer's existing session" on the second connect; no panic.

## B3. Bad-network resilience  (koh's reason to exist) — `stress-netem.sh`  [best-effort]
Inject packet loss + latency and assert koh survives and converges.
- Prefer in-guest `tc netem` on **loopback** (since `--direct` uses `127.0.0.1`): `adb root` (works on
  `google_apis`), then `tc qdisc add dev lo root netem loss 20% delay 80ms`. **Verify `tc` exists on
  the image first** — if it's absent, SKIP with a clear note (toybox may lack it; document the
  host-server alternative: run the server on the Mac and throttle the emulator's data network via the
  emulator console `network delay/speed`).
- With netem active, run a `--shell <flood-script>` session whose script writes a **sentinel** as its
  last line; assert the sentinel appears (QUIC rode out the loss end-to-end), the session survives,
  RSS stays bounded, no panic. Remove the qdisc in cleanup (`tc qdisc del dev lo root`).
- Gate behind a knob (e.g. `KOH_STRESS_NETEM=1`) so it's opt-in within the suite.

## B4. Real discovery / relay bare-id connection  (end-to-end DNS-fix validation) — `stress-relay-discovery.sh`  [best-effort, needs internet]
Everything else uses `--local`/`--direct`, which *constructs* the resolver but does no DNS lookup.
This connects via a **bare node-id** over the public relay, exercising real discovery DNS resolution
with the Android-pinned `8.8.8.8` resolver.
- Check connectivity first (e.g. the device can reach the internet); SKIP cleanly if not.
- Start the server with the **default** profile (no `--local`) so it registers with discovery/relay;
  scrape its node-id. Connect a second on-device client by **bare id** (no `--direct`), generous
  timeout.
- **Assert:** the connection establishes (server logs "client authorized" / "started a new session"),
  **no** `ndk-context` panic — proving DNS resolution actually works on Android, not just that the
  resolver constructs. Also try `KOH_DNS=1.1.1.1` to confirm the override resolves too.
- Gate behind `KOH_ANDROID_NET=1`.

## B5. Validate the new client signal code on-device — `stress-client-signals.sh`
The Ctrl-Z suspend and graceful-shutdown code shipped recently but was only unit-tested.
- **Suspend/resume:** PTY client; after `connected.`, feed `Ctrl-^ Ctrl-Z` (`\036\032`). Find
  `CLIENT_PID`; assert `/proc/$CLIENT_PID/stat` field 3 becomes `T` (the client `SIGTSTP`'d itself).
  `kill -CONT`; assert it returns to `S`/`R`, is still alive, and repaints (host capture shows output
  after resume).
- **Graceful shutdown:** PTY client; `kill -TERM $CLIENT_PID`; assert the client **exits** (process
  gone) promptly and leaves no orphan (the in-process unit tests already cover the TTY-restore path;
  verifying the tty state through adb's own PTY is not reliable, so assert clean exit).

---

## ACCEPTANCE CRITERIA
- **A1–A3** each: behavior fixed, a focused **unit test** added, all six green gates pass. **A4**:
  README updated.
- After A1, the stress scripts no longer *need* `--shell /system/bin/sh` to spawn a session on the
  device (leave them passing it explicitly is fine, but `koh serve` alone must spawn a working shell).
- **B1, B2, B5** pass on a freshly-booted arm64-v8a emulator; **B3, B4** pass when their opt-in knob +
  prerequisites (tc / internet) are present, and **SKIP cleanly** otherwise.
- `run-stress.sh` runs all applicable new tests and still reports `RESULT: PASS`; the smoke `run.sh`
  is unchanged and green.
- The whole emulator layer remains opt-in and a clean no-op (exit 0) with no device / no
  `KOH_ANDROID_EMULATOR=1`. `src/` changes are limited to A1–A3; everything else is under
  `testing/android/` + `tests/`.

## HARNESS NOTES / PITFALLS (don't relearn these)
- **Assert on the server log or `/proc`**, never client stdout: the client prints `connected.` BEFORE
  the server validates, and its TUI renders to the PTY, not a redirectable fd. Capture the TUI via
  adb's *local* stdout (`pty_connect_host_bg`), not a device-side `>redirect`.
- **iroh coalesces same-node-id connections on loopback** → use distinct key files when you need
  distinct server-side registrations; reuse one key only for per-peer behavior.
- **Typed input doesn't forward reliably** over adb's PTY → drive shell activity via
  `--shell <flood/marker-script>` + sentinel files, not by "typing" commands.
- `adb shell -t -t` gives a real PTY (needed for raw-mode client tests); a non-TTY connect errors at
  raw mode (`os error 6`) right after `connected.` — that's expected, not a bug.
- Capture `adb shell` exit codes via the `__RC__$?` sentinel (`run_remote`); `adb shell` does not
  propagate them.
- After heavy churn the emulator's loopback can degrade (auth-success goes flaky) — reboot for a clean
  run (`adb reboot` + wait for `sys.boot_completed`). Wrap every `adb shell` in `gtimeout`.
- Identify the client pid as `koh_pids` minus the server pid captured **before** the client attaches.
