# TASK: Add Android-emulator-backed tests for `koh` on Apple Silicon macOS

## GOAL
Set up an Android SDK + headless arm64 emulator on this Apple Silicon Mac, then ADD opt-in, emulator-backed tests that prove `koh`'s Android DNS-panic fix holds at runtime — without touching `koh`'s source.

## CONTEXT
You are working in the `koh` repo (`/Users/kisaczka/Desktop/code/moshers2`). `koh` is a single-crate Rust CLI: **mosh reimplemented over iroh p2p QUIC**. The binary is `koh` (clap-based, `--version`/`--help` plus subcommands `serve`, `connect <id>`, `id`). `koh id` loads-or-creates the persistent key and prints the endpoint id, then exits — a network-free smoke target. Loopback dialing uses `koh connect <id> --direct <ip:port>` against a `koh serve --allow-any` server, so no relay/internet is needed.

**Why an emulator is required (the whole point):** iroh builds a `DnsResolver` per endpoint; its default reads system DNS through Android's app JNI context. A plain CLI run via `adb shell` has **no Android app / no JNI context**, so the read used to **panic** with `ndk-context: android context was not initialized`. `koh` fixed this in `src/transport_iroh/mod.rs` (`discovery_dns_resolver`): on Android it pins Google `8.8.8.8:53`, and `KOH_DNS=<ip[:port]>` overrides on any platform. This is a **runtime-only** bug — cross-compilation / `clippy --target` only typecheck and cannot catch it. Running the bare CLI under `adb shell` on the emulator reproduces the **exact** no-JNI-context condition. That is the one bug only emulator/device testing can catch.

**Host facts (already true — do not redo):** macOS 26.5 (Tahoe), Apple Silicon arm64, zsh, Homebrew at `/opt/homebrew`. The `aarch64-linux-android` rustup target is installed (typecheck only). **NOT installed:** Android SDK, `adb`, `emulator`, `sdkmanager`, `avdmanager`, `cargo-ndk`, and no NDK linker is configured (`ANDROID_HOME`/`ANDROID_SDK_ROOT`/`NDK_HOME` unset) — so a *runnable* arm64 binary is **not** currently buildable. You must set that up.

## HARD CONSTRAINTS (read first)
- **DO NOT modify `src/`** (the koh implementation) or any existing behavior. You may only **ADD**:
  - test infra under **`testing/android/`** (follow the convention: a `README.md` + a `scripts/` dir),
  - tooling config needed to build for Android,
  - an **optional**, opt-in `tests/android_emulator.rs`.
- **Emulator tests must be OPT-IN:** env-gated behind **`KOH_ANDROID_EMULATOR=1`** (and `#[ignore]` on any Rust test). They must **never** run under default `cargo test`. With the var unset / no device, every entry point must cleanly **SKIP** (exit 0 / return), so host CI is unaffected.
- **Idempotent** (re-runnable; re-push overwrites) and **headless-runnable** (no GUI, no TTY assumptions beyond adb's char stream).
- **Keep all six green gates passing** (run them at the end, unchanged):
  1. `cargo fmt --check`
  2. `cargo clippy --all-targets`
  3. `cargo clippy --target aarch64-linux-android`
  4. `cargo test`
  5. the chaos example
  6. `cargo build --locked`
- **Host-build isolation:** anything you add (esp. a `.cargo/config.toml`) must NOT alter host `cargo build`/`test`/`clippy`. Prefer `cargo-ndk` / env-only over a committed config exactly for this reason.
- `testing/` is already in `Cargo.toml`'s `exclude`, so scripts there won't ship — keep new files under `testing/android/`.

---

## STEPS

### 1. Install SDK + create & boot a headless arm64 AVD
Command-line tools only (no IDE). The cmdline-tools cask installs the SDK root at `/opt/homebrew/share/android-commandlinetools`.

```zsh
# Prereq: a JDK for sdkmanager
brew install --cask temurin
brew install --cask android-commandlinetools

# Environment (export for this shell; also append to ~/.zshrc if you want persistence)
export ANDROID_HOME="$(brew --prefix)/share/android-commandlinetools"
export ANDROID_SDK_ROOT="$ANDROID_HOME"          # both vars; tools read different ones
export PATH="$ANDROID_HOME/cmdline-tools/latest/bin:$PATH"
export PATH="$ANDROID_HOME/platform-tools:$PATH"
export PATH="$ANDROID_HOME/emulator:$PATH"

# Accept licenses BEFORE installing (pipe `yes` or it blocks forever)
yes | sdkmanager --licenses

# Install packages. android-35 google_apis arm64-v8a is the verified-stable choice on Apple Silicon.
yes | sdkmanager \
  "platform-tools" "emulator" \
  "platforms;android-35" "build-tools;35.0.0" \
  "system-images;android-35;google_apis;arm64-v8a"
# To target API 36 instead, FIRST confirm the image exists, then swap the levels:
#   sdkmanager --list | grep 'system-images;android-36;google_apis;arm64-v8a'

# Create the AVD (echo "no" declines the custom-hardware-profile prompt)
echo "no" | avdmanager create avd \
  --name koh_test \
  --package "system-images;android-35;google_apis;arm64-v8a" \
  --device "pixel_6" --force

# Boot HEADLESS. HVF acceleration is automatic on arm64 — no -accel flag.
emulator -avd koh_test \
  -no-window -no-audio -no-boot-anim -no-snapshot \
  -gpu swiftshader_indirect -read-only &

# Wait for a REAL boot (wait-for-device is NOT "booted"). Wrap in an overall timeout.
adb start-server
adb wait-for-device
until [ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ]; do sleep 2; done
until [ "$(adb shell getprop init.svc.bootanim 2>/dev/null | tr -d '\r')" = "stopped" ]; do sleep 2; done
echo "Emulator booted."
```
- Use **`arm64-v8a`**, never x86_64 (x86_64 falls back to slow software emulation and won't match `aarch64-linux-android`).
- Clean shutdown when done: `adb emu kill`.

### 2. Set up the NDK + the `aarch64-linux-android` build (recommended: `cargo-ndk`)
```zsh
rustup target add aarch64-linux-android   # (already installed; harmless)
sdkmanager "ndk;27.2.12479018"
export ANDROID_NDK_HOME="$ANDROID_SDK_ROOT/ndk/27.2.12479018"
cargo install cargo-ndk                    # or: cargo binstall cargo-ndk
```
Pick min API **24** (the integer suffix in the NDK clang wrapper = the binary's **min** API; it must be **≤** the emulator's image API, 35).

**Alternative (no cargo-ndk): env-only NDK linker** — host-safe, no committed config:
```zsh
HOST_TAG=darwin-x86_64                      # correct even on Apple Silicon (fat binaries)
API=24
TC="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$HOST_TAG"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$TC/bin/aarch64-linux-android${API}-clang"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_AR="$TC/bin/llvm-ar"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_RUSTFLAGS="-Clink-arg=-Wl,-z,max-page-size=16384 -Clink-arg=-Wl,-z,common-page-size=16384"
```

**If (and only if) you commit a `.cargo/config.toml`:** the `[target.aarch64-linux-android]` table is only consulted when building *that* target, so it does not affect host builds — but it bakes an **absolute** NDK path into the repo. Prefer cargo-ndk or the env-only block above. If you do commit it, verify gates 1/2/4/6 still pass to prove host isolation.
```toml
# .cargo/config.toml — ANDROID-ONLY; does NOT affect host builds. Replace <NDK> with an absolute path.
[target.aarch64-linux-android]
linker = "<NDK>/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android24-clang"
ar     = "<NDK>/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-ar"
rustflags = ["-C","link-arg=-Wl,-z,max-page-size=16384","-C","link-arg=-Wl,-z,common-page-size=16384"]
```

### 3. Build the release binary
```zsh
# Recommended: cargo-ndk (-t = ABI, -p = min API). Do NOT pass -o (that's for .so jniLibs, not a bin).
cargo ndk -t arm64-v8a -p 24 build --release
# Env-only fallback: cargo build --release --target aarch64-linux-android
```
Output: `target/aarch64-linux-android/release/koh` — a **PIE ELF** linking only system libs (`libc`/`libm`/`libdl`), so it runs as a plain process with no app/JNI context. PIE is automatic; never pass `-no-pie`.

### 4. Push to `/data/local/tmp` + run the koh-specific assertions
`/data/local/tmp` is the canonical exec-allowed, shell-writable drop zone (app data dirs are SELinux no-exec for raw ELFs). `chmod 755` after every push.

```zsh
DEV=/data/local/tmp/koh
adb push target/aarch64-linux-android/release/koh "$DEV"
adb shell chmod 755 "$DEV"
```

**Critical idiom — `adb shell` swallows exit codes.** Never trust local `$?`; echo the remote `$?` via a sentinel and parse it. Wrap every call in `timeout` so blocking subcommands can't hang CI (`gtimeout` if you installed coreutils; otherwise GNU `timeout`):
```zsh
run_on_device() {            # sets OUT and RC; usage: run_on_device <args...>
  local raw
  raw="$(timeout 30 adb shell "$DEV $* ; echo __RC__\$?" 2>&1 || true)"
  RC="$(printf '%s\n' "$raw" | sed -n 's/.*__RC__\([0-9]\{1,3\}\).*/\1/p' | tail -1)"
  OUT="$(printf '%s\n' "$raw" | sed '/__RC__/d')"
  [ -n "$RC" ] || RC=255
}
```

Run the assertions **in this order**:

> **Important:** `koh id` only loads/prints the key — it does **not** bind an iroh endpoint, so it never constructs the `DnsResolver` and would not trip the panic. The regression must be driven through `koh serve` (or `connect`), which bind an endpoint. `serve` blocks on `accept()`, so run it under a short `timeout` and assert on the **ready banner** it prints *before* blocking (the endpoint binds, and `discovery_dns_resolver` runs, during setup — before the banner). Pass explicit `--key-file /data/local/tmp/…` because `adb shell` has no `$HOME` and the rootfs is read-only, so the default key path can't be created.

**Test 1 — ndk-context panic regression (HIGHEST VALUE).** `koh serve` binds the endpoint and exercises `discovery_dns_resolver` under the exact no-JNI condition.
```zsh
OUT="$(timeout 12 adb shell "$DEV serve --allow-any --local --key-file /data/local/tmp/koh-server.key" 2>&1 || true)"
adb shell "pkill -f $DEV" 2>/dev/null   # serve was killed by timeout; clean up any orphan
# PASS iff: OUT contains the "koh server ready" banner with a 64-hex endpoint id
#           AND  OUT does NOT contain "ndk-context: android context was not initialized"
#           AND  OUT does NOT contain "panicked"
# (Exit code is meaningless here — the timeout kills the blocking server; assert on OUTPUT only.)
```

**Test 2 — `KOH_DNS` override** (exercises the env-var branch of `discovery_dns_resolver` on Android):
```zsh
OUT="$(timeout 12 adb shell "KOH_DNS=1.1.1.1 $DEV serve --allow-any --local --key-file /data/local/tmp/koh-server.key" 2>&1 || true)"
adb shell "pkill -f $DEV" 2>/dev/null
# PASS iff: banner + 64-hex id present, no "ndk-context"/panic string.
```

**Test 3 — on-device loopback smoke (serve + connect, no network).** Start `koh serve --allow-any` in the background on-device, capture its id + port from its log, then `koh connect <id> --direct 127.0.0.1:<port>` with non-interactive input. Adapt the exact serve/connect flags and log-parsing to what the binary actually prints (run `koh serve --help` / `koh connect --help` on-device first; do NOT guess flags). Use `--predict never` or equivalent for determinism.
```zsh
# sketch — verify real flags against --help before finalizing:
LOG=/data/local/tmp/koh-server.log
adb shell "rm -f $LOG; nohup $DEV serve --allow-any --local --key-file /data/local/tmp/koh-server.key >$LOG 2>&1 &"
sleep 3
SRV="$(adb shell cat $LOG | tr -d '\r')"
SERVER_ID="$(printf '%s' "$SRV" | grep -oE '[0-9a-f]{64}' | head -1)"
# the port is the ":NNNN" on the "--direct <this-host-ip>:PORT" connect-hint line (NOT a QR digit)
SERVER_PORT="$(printf '%s' "$SRV" | grep -- '--direct' | grep -oE ':[0-9]+' | tail -1 | tr -d ':')"
# No TTY under `adb shell`, so the client prints "connected." then errors at raw mode — that's expected.
OUT="$(timeout 20 adb shell "$DEV connect $SERVER_ID --direct 127.0.0.1:$SERVER_PORT --key-file /data/local/tmp/koh-client.key --predict never" 2>&1 || true)"
adb shell "pkill -f $DEV" 2>/dev/null
# PASS iff: client OUT contains "connected." (handshake completed over loopback — both sides bound an
#           endpoint on-device), and NEITHER side prints "ndk-context"/panic. The trailing
#           "entering raw mode … (os error 6)" from the missing TTY is expected and ignored.
```
> Note: do **not** install the Termux APK — a real app *has* a JNI context and would NOT reproduce the bug. The bare `adb shell` CLI is the correct (and sufficient) reproduction.

### 5. Wrap it: runner + README (+ optional Rust gate)
Create this layout:
```
testing/android/
├── README.md                         # why emulator testing; what's tested; setup + run; constraints
├── .env.example                      # KOH_ANDROID_EMULATOR=1, ANDROID_DEVICE, KOH_BUILD_TARGET, ANDROID_KOH_PATH
└── scripts/
    ├── build-android.sh              # cross-compile (cargo-ndk, else env NDK linker); idempotent (--force to rebuild)
    ├── test-dns-resolver.sh          # Test 1
    ├── test-dns-override.sh          # Test 2
    ├── test-loopback-e2e.sh          # Test 3
    └── run.sh                        # orchestrates: guard → build → push → run 1,2,3 → report; exit 0 all-pass
```
**`run.sh` requirements** (single source of truth):
- Guard/skip cleanly (exit 0) if `KOH_ANDROID_EMULATOR != 1`, if `adb` is absent, or if `adb devices` shows no `device`-state entry.
- Require `ANDROID_NDK_HOME`; `adb wait-for-device` + poll `sys.boot_completed == 1` before pushing.
- Build via cargo-ndk when present, else the env-only NDK linker block.
- `adb push` + `chmod 755` (idempotent re-push), then run Tests 1→2→3 using the `__RC__$?` sentinel + `timeout`.
- Print `PASS`/`FAIL` per test; exit non-zero on any failure, `0` on all-pass.
- `set -eu`; POSIX `sh`-compatible; absolute paths derived from the script dir.

**Optional `tests/android_emulator.rs`** — opt-in gate matching koh's `tests/*.rs` style; it must be a no-op under default `cargo test`:
```rust
//! Opt-in Android emulator smoke. Runs ONLY with KOH_ANDROID_EMULATOR=1 + a device. No-op otherwise.
use std::process::Command;

#[test]
#[ignore = "requires a running Android emulator + NDK; opt in with KOH_ANDROID_EMULATOR=1"]
fn android_emulator_smoke() {
    if std::env::var_os("KOH_ANDROID_EMULATOR").as_deref() != Some(std::ffi::OsStr::new("1")) {
        eprintln!("skipping: set KOH_ANDROID_EMULATOR=1"); return;
    }
    let manifest = env!("CARGO_MANIFEST_DIR");
    let status = Command::new("sh")
        .arg(format!("{manifest}/testing/android/scripts/run.sh"))
        .status().expect("failed to launch run.sh");
    assert!(status.success(), "android emulator smoke test failed");
}
```
Invoke explicitly (both gates required, so it never runs by accident):
```zsh
KOH_ANDROID_EMULATOR=1 ANDROID_NDK_HOME=... cargo test --test android_emulator -- --ignored --nocapture
```

---

## ACCEPTANCE CRITERIA
- The string **`ndk-context: android context was not initialized`** (and `panicked`) **never appears** in any test's output/logcat.
- `koh serve` on-device prints its **"koh server ready"** banner with a **64-hex-char** endpoint id (Tests 1 and 2, the latter with `KOH_DNS=1.1.1.1`) — proving the endpoint bound and the `DnsResolver` was constructed.
- The loopback **connect establishes** (client reaches "connected.", server logs auth/attach), both sides exit 0, no panic.
- `testing/android/scripts/run.sh` exits **0** when the emulator is up and `KOH_ANDROID_EMULATOR=1`; and exits **0 (clean SKIP)** with the var unset or no device.
- **`src/` is unchanged.** New files live only under `testing/android/`, `tests/android_emulator.rs`, and (optionally) `.cargo/config.toml`.
- **All six green gates still pass**, proving host-build isolation:
  `cargo fmt --check` · `cargo clippy --all-targets` · `cargo clippy --target aarch64-linux-android` · `cargo test` · chaos example · `cargo build --locked`.

## TROUBLESHOOTING / PITFALLS
- **License hang:** `sdkmanager --licenses` blocks on per-license y/N — always `yes | …`, and accept licenses *before* installing packages.
- **`cmdline-tools/latest/` is mandatory:** the Homebrew cask lays it out correctly; a manual zip extracts to `cmdline-tools/bin` and `sdkmanager` won't find itself — move it under `latest/`.
- **Headless on Apple Silicon:** HVF is automatic on arm64 (no `-accel`/`-qemu`). Use `-gpu swiftshader_indirect` (host-GPU mode crashes windowless); `-no-snapshot` forces a clean cold boot; `-read-only` allows parallel runs.
- **Boot wait:** `adb wait-for-device` returns before Android is up — you MUST poll `getprop sys.boot_completed == 1` (and ideally `init.svc.bootanim == stopped`). Wrap polls in an overall timeout (~300s) so a wedged boot doesn't hang forever. Cold arm64 boot is ~30–90s.
- **Exec location:** push/exec only from **`/data/local/tmp`** (writable + exec-allowed for the `shell` domain); `chmod 755` after every push. `adb root` works on `google_apis` (not `_playstore`) but is unnecessary since `/data/local/tmp` needs no root.
- **Exit-code propagation:** `adb shell` historically returns local `$?`=0 regardless — always parse the `__RC__$?` sentinel; missing sentinel == failure.
- **Wrong-arch / linker errors:** `Bad system call` / `not executable` / `No such file or directory` on an existing file ⇒ a host/glibc binary or missing NDK linker — rebuild via cargo-ndk or the NDK clang wrapper. `only PIE supported` ⇒ remove any `-no-pie`. `CANNOT LINK EXECUTABLE … library not found` ⇒ a non-system shared dep (koh should need only system libs).
- **API-level / triple match:** the `…android24…` wrapper makes a min-API-24 binary; it must run on an image with API **≥ 24** (your android-35 image is fine).
- **16 KB pages:** NDK **r28+** aligns to 16 KB by default; **r27** (used here) needs `-Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384` (already in the build env above; harmless elsewhere).
- **Host-build isolation:** prefer cargo-ndk / env-only over a committed `.cargo/config.toml`. If you commit one, re-run the host gates to confirm `cargo build`/`test`/`clippy` are unaffected.
- **Timeouts everywhere:** wrap every `adb shell` in `timeout`/`gtimeout`; assert against non-blocking subcommands (`--version`/`--help`/`id`) — never let `serve` block a call without a timeout.
