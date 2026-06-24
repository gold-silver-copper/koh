# shellcheck shell=sh
# Extra helpers for the koh Android STRESS tests. Sources lib.sh (device gate, build/push,
# run_remote, crash detection) and adds: process/RSS/fd sampling, a backgroundable server, and both
# non-TTY and PTY (adb shell -t -t) client drivers.
#
# Intensity knob: KOH_STRESS_LEVEL=quick (default; CI-friendly) | full (heavy soak). Each test reads
# its own iteration/duration counts via `scaled`, and they can also be overridden individually.

# shellcheck source=lib.sh
. "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)/lib.sh"

STRESS_LEVEL="${KOH_STRESS_LEVEL:-quick}"
scaled() { if [ "$STRESS_LEVEL" = full ]; then echo "$2"; else echo "$1"; fi; }

DEVICE_SHELL="${KOH_DEVICE_SHELL:-/system/bin/sh}"   # Android has no /bin/sh; sessions need this
SRV_KEY="${KOH_SRV_KEY:-/data/local/tmp/koh-server.key}"
SRV_LOG="${KOH_SRV_LOG:-/data/local/tmp/koh-server.log}"
SERVER_ID=""
SERVER_PORT=""

# --- device process sampling -----------------------------------------------------------------------
koh_pids()  { adb $ADB_SERIAL shell pidof koh 2>/dev/null | tr -d '\r'; }
koh_count() { set -- $(koh_pids); echo "$#"; }

# VmRSS (kB) of <pid>, 0 if gone.
rss_kb() {
  adb $ADB_SERIAL shell "grep -m1 VmRSS /proc/$1/status 2>/dev/null" 2>/dev/null \
    | tr -d '\r' | awk '{print $2+0; found=1} END{if(!found) print 0}'
}
# Open fd count of <pid>, 0 if gone.
fd_count() {
  adb $ADB_SERIAL shell "ls /proc/$1/fd 2>/dev/null | wc -l" 2>/dev/null | tr -d '\r' | awk '{print $1+0}'
}
# Highest VmRSS (kB) across all koh processes right now.
max_koh_rss_kb() {
  _m=0
  for _p in $(koh_pids); do _r=$(rss_kb "$_p"); [ "$_r" -gt "$_m" ] && _m=$_r; done
  echo "$_m"
}
# The koh pid that ISN'T <server-pid> (i.e. the connected client). Empty if none.
other_pid() {  # other_pid <server-pid>
  for _p in $(koh_pids); do [ "$_p" != "$1" ] && { echo "$_p"; return; }; done
}
# /proc/<pid>/stat state char (R run, S sleep, T stopped, Z zombie, …); empty if the pid is gone.
proc_state() {
  adb $ADB_SERIAL shell "cat /proc/$1/stat 2>/dev/null" 2>/dev/null | tr -d '\r' \
    | sed -E 's/^[0-9]+ \(.*\) ([A-Za-z]).*/\1/'
}
# Total CPU jiffies (utime+stime, clock ticks ~100/s) burned by <pid>; 0 if gone. Used to catch a
# busy-loop/per-event regression (coalesced work costs ~0 ticks; a per-event syscall storm burns
# thousands). Strips the "pid (comm) " prefix first so a spaced comm can't shift the field offsets.
cpu_jiffies() {
  adb $ADB_SERIAL shell "cat /proc/$1/stat 2>/dev/null" 2>/dev/null | tr -d '\r' \
    | sed -E 's/^[0-9]+ \(.*\) //' | awk '{print ($12+0)+($13+0)}'
}

# --- server lifecycle on device --------------------------------------------------------------------
# start_server "<extra serve args>" — launch detached, wait for the banner, set SERVER_ID/SERVER_PORT.
# Adds the default Android session shell unless the caller already passes its own `--shell` (clap
# rejects a duplicated `--shell`).
start_server() {
  _extra="${1:-}"
  case " $_extra " in *" --shell "*) _shellarg="" ;; *) _shellarg="--shell $DEVICE_SHELL" ;; esac
  adb $ADB_SERIAL shell "rm -f $SRV_LOG; nohup $DEVICE_BIN serve --allow-any --local $_shellarg --key-file $SRV_KEY $_extra >$SRV_LOG 2>&1 &" >/dev/null
  SERVER_ID=""; SERVER_PORT=""
  _i=0
  while [ "$_i" -lt 25 ]; do
    _s="$(cat_dev "$SRV_LOG")"
    if has_endpoint_id "$_s"; then
      SERVER_ID="$(printf '%s' "$_s" | grep -oE '[0-9a-f]{64}' | head -1)"
      SERVER_PORT="$(printf '%s' "$_s" | grep -- '--direct' | grep -oE ':[0-9]+' | tail -1 | tr -d ':')"
      [ -n "$SERVER_PORT" ] && return 0
    fi
    _i=$((_i + 1)); sleep 1
  done
  return 1
}
server_pid() { adb $ADB_SERIAL shell "pidof koh 2>/dev/null | tr ' ' '\n' | head -1" 2>/dev/null | tr -d '\r'; }
stop_all_koh() { kill_remote_koh; sleep 1; }

# --- client drivers --------------------------------------------------------------------------------
# Non-TTY connect: reaches "connected." then errors at raw mode (no TTY) and exits. Sets OUT/RC.
connect_once() {  # connect_once <key-file> [extra args]
  run_remote "$DEVICE_BIN connect $SERVER_ID --direct 127.0.0.1:$SERVER_PORT --key-file $1 --predict never ${2:-}"
}

# PTY connect (adb shell -t -t): the client gets a real TTY, enters raw mode and runs the TUI.
# Optional <feed> (printf %b) is sent to its stdin first; then stdin is held open <hold-secs>; then
# the quit escape (Ctrl-^ .) is sent so the client exits cleanly (EOF alone is unreliable over the
# PTY). A hard local timeout caps the whole thing. Output goes to <devlog>; runs in the background.
pty_connect_bg() {  # pty_connect_bg <key-file> <devlog> <hold-secs> [feed]
  _kf=$1; _log=$2; _hold=$3; _feed=${4:-}
  _cap=$((_hold + 12))
  ( { [ -n "$_feed" ] && printf '%b' "$_feed"; sleep "$_hold"; printf '\036.'; sleep 2; } \
      | to "$_cap" adb $ADB_SERIAL shell -t -t \
          "$DEVICE_BIN connect $SERVER_ID --direct 127.0.0.1:$SERVER_PORT --key-file $_kf >$_log 2>&1" \
      >/dev/null 2>&1 || true ) &
  PTY_BG_PID=$!
}

# Like pty_connect_bg, but capture the PTY stream (adb's LOCAL stdout — i.e. the rendered TUI,
# including the status/reconnect banners that go to the terminal, not to a redirected fd) to a HOST
# file. Use this when a test needs to observe what the client DRAWS, not just its pre-raw-mode stderr.
pty_connect_host_bg() {  # pty_connect_host_bg <key-file> <HOST-logfile> <hold-secs> [feed]
  _kf=$1; _hlog=$2; _hold=$3; _feed=${4:-}
  _cap=$((_hold + 12))
  : > "$_hlog"
  ( { [ -n "$_feed" ] && printf '%b' "$_feed"; sleep "$_hold"; printf '\036.'; sleep 2; } \
      | to "$_cap" adb $ADB_SERIAL shell -t -t \
          "$DEVICE_BIN connect $SERVER_ID --direct 127.0.0.1:$SERVER_PORT --key-file $_kf" \
      > "$_hlog" 2>&1 || true ) &
  PTY_BG_PID=$!
}

# Install a tiny "shell" on the device that emits output on its own, so a connecting session floods
# WITHOUT needing the client to forward typed input (which is unreliable to drive over adb's PTY).
# Point `koh serve --shell <devpath>` at it. <body> is the script body (POSIX sh).
push_flood_script() {  # push_flood_script <devpath> <body>
  _tmp="/tmp/koh-flood-$$-$(echo "$1" | tr -dc 'a-zA-Z0-9').sh"
  printf '#!/system/bin/sh\n%s\n' "$2" > "$_tmp"
  adb $ADB_SERIAL push "$_tmp" "$1" >/dev/null
  adb $ADB_SERIAL shell chmod 755 "$1"
  rm -f "$_tmp"
}

# --- device file helpers ---------------------------------------------------------------------------
cat_dev() { adb $ADB_SERIAL shell cat "$1" 2>/dev/null | tr -d '\r'; }
wait_file_contains() {  # <devfile> <substr> <secs> -> 0 if seen
  _j=0
  while [ "$_j" -lt "$3" ]; do
    case "$(cat_dev "$1")" in *"$2"*) return 0 ;; esac
    _j=$((_j + 1)); sleep 1
  done
  return 1
}
# Host-file variant (for PTY streams captured to a HOST file via pty_connect_host_bg).
wait_file_contains_host() {  # <hostfile> <substr> <secs>
  _j=0
  while [ "$_j" -lt "$3" ]; do grep -aq "$2" "$1" 2>/dev/null && return 0; _j=$((_j + 1)); sleep 1; done
  return 1
}

# --- malicious-peer deploy (security tests) --------------------------------------------------------
EVIL_DIR="${KOH_EVIL_DIR:-$REPO_ROOT/testing/android/evil-peer/target/aarch64-linux-android/release}"
EVIL_HOST="${KOH_EVIL_HOST:-$EVIL_DIR/evil-client}"
EVIL_DEV="${KOH_EVIL_DEV:-/data/local/tmp/evil-client}"
EVIL_SERVER_HOST="${KOH_EVIL_SERVER_HOST:-$EVIL_DIR/evil-server}"
EVIL_SERVER_DEV="${KOH_EVIL_SERVER_DEV:-/data/local/tmp/evil-server}"
# Push the cross-compiled malicious peer (both binaries); SKIP the test cleanly if not built.
push_evil() {
  if [ ! -x "$EVIL_HOST" ]; then
    echo "SKIP: evil-peer not built. Build it first:"
    echo "      (cd testing/android/evil-peer && CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=<ndk>/…/aarch64-linux-android24-clang cargo build --release --target aarch64-linux-android)"
    exit 0
  fi
  adb $ADB_SERIAL push "$EVIL_HOST" "$EVIL_DEV" >/dev/null
  adb $ADB_SERIAL shell chmod 755 "$EVIL_DEV"
  # The malicious server is optional (only the auth-direction tests need it).
  if [ -x "$EVIL_SERVER_HOST" ]; then
    adb $ADB_SERIAL push "$EVIL_SERVER_HOST" "$EVIL_SERVER_DEV" >/dev/null
    adb $ADB_SERIAL shell chmod 755 "$EVIL_SERVER_DEV"
  fi
}

# --- reporting -------------------------------------------------------------------------------------
STRESS_FAIL=0
ok()   { echo "  ok: $1"; }
bad()  { echo "  FAIL: $1"; STRESS_FAIL=1; }
finish() {  # finish <test-name>
  stop_all_koh
  if [ "$STRESS_FAIL" = 0 ]; then echo "PASS: $1"; exit 0; else echo "FAIL: $1"; exit 1; fi
}
