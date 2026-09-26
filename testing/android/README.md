# Android emulator tests

Runtime tests that run the cross-compiled `koh` binary on an Android emulator via `adb`. They exist
to catch one class of bug that **cross-compilation and `clippy --target` cannot**: a *runtime* panic
on Android.

## Why this tier exists

iroh builds a `DnsResolver` for every endpoint it binds. Its default reads the host's system DNS
through Android's app **JNI context** — which a plain CLI (no Android app) doesn't have, so the read
used to panic with `ndk-context: android context was not initialized`. `koh` fixes this in
`src/transport_iroh/mod.rs` (`discovery_dns_resolver`) by pinning an explicit nameserver on Android
(`KOH_DNS=<ip[:port]>` overrides).

Running the bare binary under `adb shell` reproduces the **exact** no-JNI-context condition — so it
is the only way to verify the fix actually holds at runtime. (Installing the real Termux APK would
*not* reproduce it: a real app *has* a JNI context.)

Note: `koh id` only prints the public key and never binds an endpoint, so the tests use
`koh serve` / `koh connect`, which bind an endpoint (and thus construct the `DnsResolver`).

## What it tests

| Test | Command on device | Asserts |
|------|-------------------|---------|
| `test-dns-resolver` | `koh serve --allow <id> --local` | endpoint binds + prints its id; **no** `ndk-context` panic / Rust panic |
| `test-dns-override`  | `KOH_DNS=1.1.1.1 koh serve …` | same, with the override branch active |
| `test-loopback-e2e`  | `serve` + `connect … --direct 127.0.0.1:<port>` | the server admits the client and attaches its session over loopback (both sides bind on-device); no panic |

## Constraints (by design)

- **Opt-in:** nothing runs unless `KOH_ANDROID_EMULATOR=1` **and** an emulator/device is connected.
  Otherwise every entry point prints `SKIP` and exits 0 — it never affects `cargo test` or CI.
- **Does not touch koh's sources** — this is pure out-of-band test infra (and `testing/` is excluded from
  the published crate).
- Idempotent and headless.

## One-time setup (macOS, Apple Silicon)

```sh
brew install --cask android-commandlinetools    # adb, sdkmanager, avdmanager, emulator
brew install openjdk coreutils                   # JDK for sdkmanager; gtimeout for the harness
# An NDK is needed to build the binary: `brew install --cask android-ndk` or `sdkmanager "ndk;<ver>"`.

export ANDROID_HOME="$(brew --prefix)/share/android-commandlinetools"
export ANDROID_SDK_ROOT="$ANDROID_HOME"
export JAVA_HOME=/opt/homebrew/opt/openjdk
export PATH="$JAVA_HOME/bin:$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$PATH"

yes | sdkmanager --licenses
yes | sdkmanager "platform-tools" "emulator" "system-images;android-35;google_apis;arm64-v8a"
echo "no" | avdmanager create avd --name koh_test \
  --package "system-images;android-35;google_apis;arm64-v8a" --device pixel_6 --force
```

Homebrew's `openjdk` is keg-only: `java` is not on `PATH` until `$JAVA_HOME/bin` is added, as
above, and `sdkmanager`/`avdmanager` fail without it.

Use a **`google_apis`** image, not `google_apis_playstore`: its userdebug build has `su`, which the
netem tests need for `tc`. Use an **arm64-v8a** image — it runs natively on Apple Silicon and
matches `koh`'s `aarch64-linux-android` target. The build uses `cargo-ndk` if installed, else the
NDK clang linker directly (no committed `.cargo/config.toml`, so host builds are unaffected).

The suites build what they need before they run: koh (`build-android.sh`), and for the security
and stress suites the malicious-peer harness (`evil-peer/`) too. cargo rebuilds only what changed,
so a run never tests a stale binary. To build by hand:

```sh
sh testing/android/scripts/build-android.sh        # koh
sh testing/android/scripts/build-android.sh evil   # evil-client + evil-server
```

## Run

```sh
# 1. Boot a headless emulator (leave it running)
emulator -avd koh_test -no-window -no-audio -no-boot-anim -no-snapshot \
  -gpu swiftshader_indirect -read-only &

# 2. Run the suite (builds + pushes + asserts)
KOH_ANDROID_EMULATOR=1 sh testing/android/scripts/run.sh

# …or via cargo (same thing, gated):
KOH_ANDROID_EMULATOR=1 cargo test --test android_emulator -- --ignored --nocapture

# 3. Shut the emulator down
adb emu kill
```

Individual tests are runnable on their own (e.g. `KOH_ANDROID_EMULATOR=1 sh
testing/android/scripts/test-dns-resolver.sh`); run on their own they push the binary as built, so
build first after a change. See `.env.example` for all knobs. `PROMPT.md` is the original task
brief that generated this tier.

The security suite (`run-security.sh`, or `cargo test --test android_security -- --ignored`) runs the
same way; `GREEN-security-run.txt` is a recorded passing run and `RED-security-run.txt` one against
the build before the 0.3.1 security fixes.

### Run times

Measured on an M2 Max with the `android-35` `google_apis` arm64 image, after the first build (koh
about 3.5 minutes, evil-peer about 2):

| Suite | Time |
|---|---|
| smoke (`run.sh`) | ~30 s |
| security (`run-security.sh`) | ~40 s |
| stress, `quick`, with `KOH_STRESS_NETEM=1 KOH_ANDROID_NET=1` | ~7.5 min |
| stress, `full`, the same | ~16.5 min |

### Known skips

With the setup above nothing skips. A test skips, saying why, only when the machine cannot run it:
`stress-netem` and `stress-roaming` without `su` (a user build, such as a `google_apis_playstore`
image); `stress-relay-discovery` without internet on the emulator, or when the bare-id connection
over the public relay does not establish that run (the no-`ndk-context`-panic check still applies);
and anything using evil-peer if it cannot be built.

## Stress suite

A heavier, comprehensive suite that hammers koh on the emulator under load, churn, and adverse
conditions — monitoring for crashes, panics, leaks, and resilience failures. Opt-in and CI-safe
exactly like the smoke tests; pick intensity with `KOH_STRESS_LEVEL` (`quick`, the default, or
`full` for a soak).

```sh
# all of it (boot an emulator first; ~7.5 min on quick, see Run times)
KOH_ANDROID_EMULATOR=1 sh testing/android/scripts/run-stress.sh
# heavy soak
KOH_ANDROID_EMULATOR=1 KOH_STRESS_LEVEL=full sh testing/android/scripts/run-stress.sh
# or via cargo
KOH_ANDROID_EMULATOR=1 cargo test --test android_stress -- --ignored --nocapture
# one dimension
KOH_ANDROID_EMULATOR=1 sh testing/android/scripts/stress-throughput.sh
```

| Stress test | What it hammers | Key assertions |
|---|---|---|
| `stress-bind-storm` | many rapid endpoint binds (the DNS-init path) | every bind succeeds, never an `ndk-context` panic |
| `stress-connection-churn` | rapid connect/disconnect vs one server | server survives, RSS bounded (no per-connection leak), no panic |
| `stress-concurrent-clients` | N simultaneous distinct-peer sessions | all connect, server survives, RSS bounded |
| `stress-evil-peer` *(needs the cross-compiled evil-peer; else self-SKIPs)* | the **malicious-peer harness**: crafted stream/flood attacks (an over-cap message prefix, an over-cap input, a second input stream, input floods, resize/keys floods, garbage, a wrong ALPN) + an admission-stall from a malicious **client**, and bad-admit/stall-admit from a malicious **server** | every attack is proven to have run, and the server stays **alive + memory-bounded + panic-free** under all of them (witness session intact, fresh client still admitted); a wrong ALPN is refused by the handshake; a client that never accepts its admission ack holds no other client up; and a real koh **client refuses** a server that sends a bad admission byte or never admits (it exits with that refusal) |
| `stress-signal-storm` | repeated SIGTERM/SIGINT teardown | every signal drains gracefully, no orphan, no panic |
| `stress-throughput` | server-side flood of 2×10⁴ (`quick`) to 2×10⁵ (`full`) lines | whole flood processed end-to-end, no panic, server RSS bounded |
| `stress-memory-longevity` | unbounded output for tens of seconds | RSS plateaus (no leak) under an absolute cap, no panic |
| `stress-reconnect-restart` | hard-kill the server under a live client | client rides out the drop, stays alive (doesn't exit to shell), surfaces the link-down banner |
| `stress-client-freeze` | `SIGSTOP`/`SIGCONT` the **client** for a SHORT gap (<20s) — a brief screen-off | session rides the freeze out on the *same* connection (no detach/reconnect), client survives |
| `stress-client-wake-reconnect` | `SIGSTOP`/`SIGCONT` the **client** for a LONG gap (>20s, <300s idle) — a long screen-off | the wall-clock freeze detector fires: the client *proactively* re-dials and the server **reattaches within ~15s** (not after the ~5-min idle timeout), landing back in the **same** session (shell reused), client survives |
| `stress-reattach-continuity` | disconnect then reconnect the same peer | the shell is spawned **once** and *reused* (not recreated) — true "close the lid, reopen" continuity |
| `stress-client-signals` | Ctrl-^ Ctrl-Z suspend + SIGTERM | the suspend path runs (prints its notice) and the client keeps running — under `adb shell` koh's process group is orphaned, so the kernel discards its own `SIGTSTP`; the stop itself is tested off-device. SIGTERM exits cleanly, no orphan |
| `stress-netem` *(opt-in)* | a long **chaos soak**: cycling loss/jitter/reorder/dup, heavy loss, total blackouts, high latency on `lo` (default 72s, `full` 300s) | session survives *every* phase on one connection (no detach/reconnect), no crash, no leak |
| `stress-roaming` *(opt-in)* | a 14s total loopback outage (100% loss) mid-session, then recover | client draws its link-down banner (after 9s of silence: three missed heartbeats) and rides out the outage on the *same* connection (no detach/reconnect) |
| `stress-relay-discovery` *(opt-in)* | bare-id connect over the public relay | real discovery **DNS resolution** works on Android (not just resolver construction) |

The opt-in tests self-SKIP (exit 0) unless enabled: `KOH_STRESS_NETEM=1` (netem + roaming; needs
`su 0 tc`, i.e. a userdebug image) and `KOH_ANDROID_NET=1` (relay-discovery; needs the emulator to
reach the internet). Do not `adb root` for them: it restarts the device shell as uid 0, and koh then
refuses the harness's key files, which belong to the shell user.

### Migrated from the old `testing/tier2/` (Docker network-realism scaffolding)

`tier2/` was stale, never-run Docker scaffolding (it referenced the pre-rename `rmosh-server`/
`rmosh-client` binaries). Its coverage now lives here:

- **OS-level chaos** (`tier2/scripts/netem.sh`) → `stress-netem` — the same `tc netem`
  delay±jitter/loss/reorder/duplicate, run beneath the real QUIC stack on the device.
- **Relay path** (server + client meet only via a relay) → `stress-relay-discovery` — a bare-id
  connection over the public relay (the path the Android DNS fix exists for).
- **Roaming / outage resilience** → `stress-roaming` — a transient total network outage mid-session
  (the single-host analogue of "the network went away and came back").

What a **single emulator can't** faithfully reproduce, by design — and where it's covered instead:

- **True roaming / QUIC connection migration** (the client's *source IP* changing while the server
  stays reachable) needs two network paths. One emulator over loopback has one. `stress-roaming`
  covers the user-facing resilience (session survives the outage); a literal IP-change migration
  needs two hosts (or the old Docker multi-network setup).
- **NAT-traversal hole-punching** needs a real NAT topology; the relay *path* is exercised by
  `stress-relay-discovery`, but punching through to a direct path isn't single-host-reproducible.

Notes on the harness (learned the hard way against a real emulator):
- All cross-process assertions read the **server log** or sample `/proc`: the client prints nothing
  once it connects, and its TUI renders to the PTY (not a redirectable fd). A connection is proven by
  the server's line for that client's session (`started a new session` / `reattaching to this
  peer's existing session`); a running client process may still be dialing.
- Each test tracks the pid of the server it started (not "the first koh"), and its teardown fails the
  test if a koh outlives SIGTERM by 10s, printing what it is waiting on.
- A test that stops early under `set -e` reports it as a failure instead of ending silently.
- Floods are driven **server-side** via a `--shell <flood-script>` (typed input doesn't forward
  reliably over `adb`'s PTY); RSS/leak checks sample `VmRSS` from `/proc/<pid>/status`.
- iroh **coalesces same-node-id connections on loopback**, so tests that need N distinct
  registrations use N distinct keys; per-peer tests (rate limiter) reuse one key and space attempts.

## Files

```
testing/android/
├── README.md              # this file
├── PROMPT.md              # the task brief
├── .env.example           # KOH_ANDROID_EMULATOR + SDK/NDK paths + knobs
├── GREEN-security-run.txt # a recorded passing security run
├── RED-security-run.txt   # the security run against koh 0.3.0, before its fixes
├── evil-peer/             # the malicious-peer harness (evil-client, evil-server); not published
└── scripts/
    ├── lib.sh             # shared helpers (skip gate, build/push, adb run + exit-code capture)
    ├── stress-lib.sh      # stress helpers (RSS/fd sampling, server + PTY client drivers, flood scripts)
    ├── build-android.sh   # cross-compile koh, or `evil` for evil-peer (cargo-ndk, else NDK clang)
    ├── test-dns-resolver.sh
    ├── test-dns-override.sh
    ├── test-loopback-e2e.sh
    ├── run.sh             # smoke orchestrator: guard → build → push → run smoke tests → tally
    ├── sec-resize-oom-server.sh   # H-1: a huge resize must not blow up the server's memory
    ├── sec-resize-zero-panic.sh   # M-2: a (0,0) resize must not panic the server
    ├── sec-key-perms.sh           # M-1: the key file is 0600
    ├── sec-env-leak.sh            # L-4: no KOH_* variable reaches the session shell
    ├── run-security.sh    # security orchestrator
    ├── stress-bind-storm.sh
    ├── stress-connection-churn.sh
    ├── stress-concurrent-clients.sh
    ├── stress-signal-storm.sh
    ├── stress-throughput.sh
    ├── stress-memory-longevity.sh
    ├── stress-reconnect-restart.sh
    ├── stress-evil-peer.sh
    ├── stress-client-freeze.sh
    ├── stress-client-wake-reconnect.sh
    ├── stress-reattach-continuity.sh
    ├── stress-client-signals.sh
    ├── stress-netem.sh            # opt-in (KOH_STRESS_NETEM=1): tc delay/jitter/loss/reorder/dup
    ├── stress-roaming.sh          # opt-in (KOH_STRESS_NETEM=1): total-outage resilience (ex-tier2 roam)
    ├── stress-relay-discovery.sh  # opt-in (KOH_ANDROID_NET=1): real DNS via relay
    └── run-stress.sh      # stress orchestrator: guard → build → push → run all stress tests → tally
```
