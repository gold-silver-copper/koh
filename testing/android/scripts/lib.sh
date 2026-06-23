# shellcheck shell=sh
# Shared helpers for the koh Android-emulator test harness. Sourced by the other scripts.
#
# Everything here is POSIX sh. The harness is OPT-IN: it does nothing unless KOH_ANDROID_EMULATOR=1
# and an emulator/device is connected — so it can never affect the normal `cargo test` run.

# --- paths -----------------------------------------------------------------------------------------
# Resolve the scripts dir and repo root from the script that sourced us ($0 stays the running script
# in POSIX sh). All scripts live in testing/android/scripts/, so repo root is three levels up.
SCRIPTS_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
REPO_ROOT="$(CDPATH= cd -- "$SCRIPTS_DIR/../../.." && pwd -P)"

ANDROID_TARGET="${KOH_ANDROID_TARGET:-aarch64-linux-android}"
HOST_BIN="${KOH_HOST_BIN:-$REPO_ROOT/target/$ANDROID_TARGET/release/koh}"
DEVICE_BIN="${KOH_DEVICE_BIN:-/data/local/tmp/koh}"
ADB_TIMEOUT="${KOH_ADB_TIMEOUT:-30}"        # cap on a single non-blocking adb shell call (seconds)

# The strings that mean the Android DNS fix regressed (or any crash). Tests fail if these appear.
PANIC_NDK="ndk-context: android context was not initialized"
PANIC_RUST="panicked"

# --- SDK environment (macOS / Homebrew default; overridable via ANDROID_HOME) ----------------------
bootstrap_sdk_env() {
  : "${ANDROID_HOME:=${ANDROID_SDK_ROOT:-/opt/homebrew/share/android-commandlinetools}}"
  ANDROID_SDK_ROOT="$ANDROID_HOME"
  export ANDROID_HOME ANDROID_SDK_ROOT
  for d in "$ANDROID_HOME/platform-tools" "$ANDROID_HOME/emulator" \
           "$ANDROID_HOME/cmdline-tools/latest/bin" "/opt/homebrew/opt/openjdk/bin"; do
    [ -d "$d" ] && case ":$PATH:" in *":$d:"*) ;; *) PATH="$d:$PATH" ;; esac
  done
  export PATH
  [ -n "${JAVA_HOME:-}" ] || { [ -d /opt/homebrew/opt/openjdk ] && export JAVA_HOME=/opt/homebrew/opt/openjdk; }
}

# --- portable timeout (gtimeout / timeout / none) --------------------------------------------------
if command -v gtimeout >/dev/null 2>&1; then _TIMEOUT=gtimeout
elif command -v timeout  >/dev/null 2>&1; then _TIMEOUT=timeout
else _TIMEOUT=""; fi
# to <seconds> <cmd...> — run with a timeout if one is available, else run plainly.
to() { _t=$1; shift; if [ -n "$_TIMEOUT" ]; then "$_TIMEOUT" "$_t" "$@"; else "$@"; fi; }

# --- device selection / skip gate ------------------------------------------------------------------
# Sets ADB_SERIAL ("-s <serial>" or empty). Returns 0 iff opted-in AND exactly-usable device present.
device_ready() {
  [ "${KOH_ANDROID_EMULATOR:-}" = "1" ] || return 1
  command -v adb >/dev/null 2>&1 || return 1
  adb start-server >/dev/null 2>&1 || true
  # Lines like "emulator-5554\tdevice"; ignore "offline"/"unauthorized" and the header.
  _serials="$(adb devices 2>/dev/null | awk 'NR>1 && $2=="device"{print $1}')"
  [ -n "$_serials" ] || return 1
  if [ -n "${ANDROID_SERIAL:-}" ]; then ADB_SERIAL="-s $ANDROID_SERIAL"
  else ADB_SERIAL="-s $(printf '%s\n' "$_serials" | head -1)"; fi
  export ADB_SERIAL
  return 0
}

# Print a SKIP line and exit 0 (a clean no-op) unless a device is usable.
require_device_or_skip() {
  if ! device_ready; then
    if [ "${KOH_ANDROID_EMULATOR:-}" != "1" ]; then
      echo "SKIP: set KOH_ANDROID_EMULATOR=1 to enable the Android emulator tests"
    else
      echo "SKIP: no Android device/emulator in 'device' state (boot one first; see testing/android/README.md)"
    fi
    exit 0
  fi
}

adb_() { to "$ADB_TIMEOUT" adb $ADB_SERIAL "$@"; }

# Wait until the device finishes booting (sys.boot_completed=1), bounded.
wait_for_boot() {
  _deadline=$(( $(date +%s) + ${KOH_BOOT_TIMEOUT:-300} ))
  adb $ADB_SERIAL wait-for-device || return 1
  while [ "$(adb $ADB_SERIAL shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" != "1" ]; do
    [ "$(date +%s)" -lt "$_deadline" ] || { echo "ERROR: timed out waiting for boot" >&2; return 1; }
    sleep 2
  done
}

# --- binary deploy ---------------------------------------------------------------------------------
ensure_binary() {
  if [ ! -x "$HOST_BIN" ]; then
    echo "Android binary missing; building it…"
    sh "$SCRIPTS_DIR/build-android.sh" || return 1
  fi
  [ -x "$HOST_BIN" ]
}

push_binary() {
  ensure_binary || return 1
  adb_ push "$HOST_BIN" "$DEVICE_BIN" >/dev/null
  adb_ shell chmod 755 "$DEVICE_BIN"
}

# --- run a remote command, capturing combined output + a reliable exit code ------------------------
# `adb shell` does not propagate the remote exit status, so we append a sentinel and parse it.
# Sets OUT (stdout+stderr, sentinel stripped) and RC (remote exit code, 255 if unknown).
# Usage: run_remote "<full remote command, e.g. ENV=v /data/local/tmp/koh id>"
run_remote() {
  _raw="$(adb_ shell "$1 ; echo __RC__\$?" 2>&1 || true)"
  OUT="$(printf '%s\n' "$_raw" | sed '/__RC__/d')"
  RC="$(printf '%s\n' "$_raw" | sed -n 's/.*__RC__\([0-9][0-9]*\).*/\1/p' | tail -1)"
  [ -n "$RC" ] || RC=255
}

# Run a command that BLOCKS (e.g. `koh serve`): run it for <secs>, then it is killed; we keep its
# output. RC is meaningless here (the timeout kills it) — assert on OUT. Sets OUT.
# Requires a real timeout tool: a blocking serve with no timeout would hang the harness.
run_remote_blocking() {
  _secs=$1; shift
  if [ -z "$_TIMEOUT" ]; then
    echo "  ERROR: no 'gtimeout'/'timeout' on PATH — install coreutils (brew install coreutils)" >&2
    OUT=""; return 1
  fi
  OUT="$("$_TIMEOUT" "$_secs" adb $ADB_SERIAL shell "$1" 2>&1 || true)"
  kill_remote_koh
}

# Kill any koh processes left on the device (serve is detached/blocking; keep re-runs clean).
kill_remote_koh() {
  adb $ADB_SERIAL shell "pkill -f $DEVICE_BIN" >/dev/null 2>&1 || true
}

# --- assertions ------------------------------------------------------------------------------------
contains()     { case "$2" in *"$1"*) return 0 ;; *) return 1 ;; esac; }
# A 64-hex endpoint id appears anywhere in $1.
has_endpoint_id() { printf '%s' "$1" | grep -qE '[0-9a-f]{64}'; }
# Fail (return 1) if either crash signature is present in $1.
assert_no_crash() {
  if contains "$PANIC_NDK" "$1"; then echo "  !! found the ndk-context panic — the Android DNS fix regressed"; return 1; fi
  if contains "$PANIC_RUST" "$1"; then echo "  !! found a Rust panic in koh's output"; return 1; fi
  return 0
}
