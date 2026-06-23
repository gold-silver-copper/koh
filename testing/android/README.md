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
| `test-dns-resolver` | `koh serve --allow-any --local` | endpoint binds + prints its id; **no** `ndk-context` panic / Rust panic |
| `test-dns-override`  | `KOH_DNS=1.1.1.1 koh serve …` | same, with the override branch active |
| `test-loopback-e2e`  | `serve` + `connect … --direct 127.0.0.1:<port>` | client reaches `connected.` over loopback (both sides bind on-device); no panic |

## Constraints (by design)

- **Opt-in:** nothing runs unless `KOH_ANDROID_EMULATOR=1` **and** an emulator/device is connected.
  Otherwise every entry point prints `SKIP` and exits 0 — it never affects `cargo test` or CI.
- **Does not touch `src/`** — this is pure out-of-band test infra (and `testing/` is excluded from
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

Use an **arm64-v8a** image — it runs natively on Apple Silicon and matches `koh`'s
`aarch64-linux-android` target. The build uses `cargo-ndk` if installed, else the NDK clang linker
directly (no committed `.cargo/config.toml`, so host builds are unaffected).

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
testing/android/scripts/test-dns-resolver.sh`). See `.env.example` for all knobs. `PROMPT.md` is the
original task brief that generated this tier.

## Stress suite

A heavier, comprehensive suite that hammers koh on the emulator under load, churn, and adverse
conditions — monitoring for crashes, panics, leaks, and resilience failures. Opt-in and CI-safe
exactly like the smoke tests; pick intensity with `KOH_STRESS_LEVEL` (`quick`, the default, or
`full` for a soak).

```sh
# all of it (boot an emulator first; ~5–10 min on quick)
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
| `stress-auth-ratelimit` | failed-auth flood on a passphrase server | no wrong passphrase authorized, server survives, legit client still gets in (limiter engagement = telemetry) |
| `stress-signal-storm` | repeated SIGTERM/SIGINT teardown | every signal drains gracefully, no orphan, no panic |
| `stress-throughput` | server-side flood of 10⁴–10⁵ lines | whole flood processed end-to-end, no panic, server RSS bounded |
| `stress-memory-longevity` | unbounded output for tens of seconds | RSS plateaus (no leak) under an absolute cap, no panic |
| `stress-reconnect-restart` | hard-kill the server under a live client | client rides out the drop, stays alive (doesn't exit to shell), surfaces the link-down banner |

Notes on the harness (learned the hard way against a real emulator):
- All cross-process assertions read the **server log** or sample `/proc` — the client prints
  `connected.` *before* the server validates, and its TUI renders to the PTY (not a redirectable fd).
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
└── scripts/
    ├── lib.sh             # shared helpers (skip gate, build/push, adb run + exit-code capture)
    ├── stress-lib.sh      # stress helpers (RSS/fd sampling, server + PTY client drivers, flood scripts)
    ├── build-android.sh   # cross-compile (cargo-ndk, else NDK clang linker); idempotent
    ├── test-dns-resolver.sh
    ├── test-dns-override.sh
    ├── test-loopback-e2e.sh
    ├── run.sh             # smoke orchestrator: guard → build → push → run smoke tests → tally
    ├── stress-bind-storm.sh
    ├── stress-connection-churn.sh
    ├── stress-concurrent-clients.sh
    ├── stress-auth-ratelimit.sh
    ├── stress-signal-storm.sh
    ├── stress-throughput.sh
    ├── stress-memory-longevity.sh
    ├── stress-reconnect-restart.sh
    └── run-stress.sh      # stress orchestrator: guard → build → push → run all stress tests → tally
```
