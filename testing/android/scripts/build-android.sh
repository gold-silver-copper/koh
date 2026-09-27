#!/bin/sh
# Cross-compile for the Android emulator (aarch64-linux-android, release).
#
#   build-android.sh          koh itself (target/aarch64-linux-android/release/koh)
#   build-android.sh evil     the malicious-peer harness, evil-client and evil-server
#                             (testing/android/evil-peer/target/aarch64-linux-android/release/)
#
# Prefers `cargo-ndk` if installed; otherwise drives the NDK clang linker directly via per-target
# CARGO_TARGET_* env vars (no committed .cargo/config.toml, so host builds stay untouched). The NDK
# is located via ANDROID_NDK_HOME / NDK_HOME, else the Homebrew `android-ndk` cask.
set -eu

HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
. "$HERE/lib.sh"

API="${KOH_ANDROID_API:-24}"   # min API of the built binary; must be <= the emulator image API

case "${1:-koh}" in
  koh)
    DIR="$REPO_ROOT"
    ARTIFACTS="$HOST_BIN"
    ;;
  evil)
    DIR="$REPO_ROOT/testing/android/evil-peer"
    ARTIFACTS="$DIR/target/$ANDROID_TARGET/release/evil-client $DIR/target/$ANDROID_TARGET/release/evil-server"
    ;;
  *)
    echo "usage: build-android.sh [koh|evil]" >&2
    exit 2
    ;;
esac

built() { for a in $ARTIFACTS; do [ -x "$a" ] || return 1; done; }

# Always run cargo: it rebuilds only what changed, so a run never tests a stale binary.
rustup target add "$ANDROID_TARGET" >/dev/null 2>&1 || true
cd "$DIR"

if command -v cargo-ndk >/dev/null 2>&1; then
  echo "Building $DIR with cargo-ndk (-t arm64-v8a -p $API)…"
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
  echo "Building $DIR with NDK linker: $CLANG"
  CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$CLANG" \
  CARGO_TARGET_AARCH64_LINUX_ANDROID_AR="$TB/llvm-ar" \
    cargo build --release --target "$ANDROID_TARGET"
fi

built || { echo "ERROR: build finished but one of $ARTIFACTS is missing" >&2; exit 1; }
for a in $ARTIFACTS; do
  echo "Built: $a"
  file "$a" 2>/dev/null || true
done
