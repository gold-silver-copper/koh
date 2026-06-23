#!/bin/sh
# Cross-compile koh for the Android emulator (aarch64-linux-android, release).
#
# Prefers `cargo-ndk` if installed; otherwise drives the NDK clang linker directly via per-target
# CARGO_TARGET_* env vars (no committed .cargo/config.toml, so host builds stay untouched). The NDK
# is located via ANDROID_NDK_HOME / NDK_HOME, else the Homebrew `android-ndk` cask.
set -eu

HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
. "$HERE/lib.sh"

API="${KOH_ANDROID_API:-24}"   # min API of the built binary; must be <= the emulator image API

# Already built? (callers may force a rebuild by deleting the artifact)
if [ -x "$HOST_BIN" ] && [ -z "${KOH_FORCE_BUILD:-}" ]; then
  echo "Android binary already present: $HOST_BIN (set KOH_FORCE_BUILD=1 to rebuild)"
  exit 0
fi

rustup target add "$ANDROID_TARGET" >/dev/null 2>&1 || true

if command -v cargo-ndk >/dev/null 2>&1; then
  echo "Building with cargo-ndk (-t arm64-v8a -p $API)…"
  cargo ndk -t arm64-v8a -p "$API" build --release
else
  # Locate the NDK.
  NDK="${ANDROID_NDK_HOME:-${NDK_HOME:-}}"
  if [ -z "$NDK" ] && [ -d /opt/homebrew/share/android-ndk ]; then
    NDK="$(cd /opt/homebrew/share/android-ndk && pwd -P)"
  fi
  [ -n "$NDK" ] && [ -d "$NDK" ] || {
    echo "ERROR: no NDK found. Install one (sdkmanager 'ndk;<ver>' or 'brew install --cask android-ndk')" >&2
    echo "       and set ANDROID_NDK_HOME, or install cargo-ndk (cargo install cargo-ndk)." >&2
    exit 1
  }
  TB="$(ls -d "$NDK"/toolchains/llvm/prebuilt/*/bin 2>/dev/null | head -1)"
  [ -n "$TB" ] || { echo "ERROR: NDK toolchain bin not found under $NDK" >&2; exit 1; }
  CLANG="$TB/aarch64-linux-android${API}-clang"
  [ -x "$CLANG" ] || { echo "ERROR: $CLANG missing (API $API not in this NDK?)" >&2; exit 1; }
  echo "Building with NDK linker: $CLANG"
  CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$CLANG" \
  CARGO_TARGET_AARCH64_LINUX_ANDROID_AR="$TB/llvm-ar" \
    cargo build --release --target "$ANDROID_TARGET"
fi

[ -x "$HOST_BIN" ] || { echo "ERROR: build finished but $HOST_BIN is missing" >&2; exit 1; }
echo "Built: $HOST_BIN"
file "$HOST_BIN" 2>/dev/null || true
