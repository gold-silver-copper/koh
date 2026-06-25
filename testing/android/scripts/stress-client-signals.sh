#!/bin/sh
# Stress: validate the client signal handling on a real device. Two behaviors that shipped recently
# but were only unit-tested off-device:
#   (a) Ctrl-^ Ctrl-Z suspend → the client SIGTSTP's itself (process state T); SIGCONT resumes it.
#   (b) SIGTERM → the client shuts down cleanly (exits, no orphan; Drop restores the TTY).
set -eu
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
. "$HERE/stress-lib.sh"

require_device_or_skip
push_binary

echo "Stress: client signals — Ctrl-^ Ctrl-Z suspend/resume + SIGTERM graceful shutdown (level=$STRESS_LEVEL)"

allow_client_key /data/local/tmp/koh-siga.key
allow_client_key /data/local/tmp/koh-sigb.key
start_server "" || { bad "server failed to start"; finish "stress-client-signals"; }
SPID="$(server_pid)"

# --- (a) Ctrl-^ Ctrl-Z suspend path -----------------------------------------------------------------
# Note: the actual kernel stop (SIGTSTP) needs real job control — a controlling terminal with koh in
# the *foreground* process group (e.g. Termux). Under `adb shell` koh's process group is orphaned, so
# POSIX has the kernel DISCARD the self-SIGTSTP (it doesn't stop). So on-device we assert the suspend
# CODE PATH ran (it hands the terminal back and prints the suspend notice); the kernel-stop + resume
# is covered by the in-process unit tests.
HLOG="/tmp/koh-sig-a-$$.log"; : > "$HLOG"
( sleep 5; printf '\036\032'; sleep 8; printf '\036.'; sleep 2 ) \
  | to 30 adb $ADB_SERIAL shell -t -t \
      "$KENV $DEVICE_BIN connect $SERVER_ID --direct 127.0.0.1:$SERVER_PORT --key-file /data/local/tmp/koh-siga.key" \
  > "$HLOG" 2>&1 &
SIGA_BG=$!

ran=0; w=0
while [ "$w" -lt 16 ]; do
  grep -aq 'koh suspended' "$HLOG" 2>/dev/null && { ran=1; break; }
  w=$((w + 1)); sleep 1
done
[ "$ran" = 1 ] && ok "Ctrl-^ Ctrl-Z ran the suspend path on-device (printed the suspend notice, handed back the TTY)" \
  || bad "the suspend path did not run on Ctrl-^ Ctrl-Z (no suspend notice)"
# The client must not have crashed doing it (SIGTSTP discarded → it keeps running here).
{ [ -n "$(other_pid "$SPID")" ] || grep -aq 'koh suspended' "$HLOG"; } && ok "client handled the suspend without crashing" || bad "client crashed during the suspend path"

wait "$SIGA_BG" 2>/dev/null || true
rm -f "$HLOG"
adb $ADB_SERIAL shell "pkill -f $DEVICE_BIN" >/dev/null 2>&1 || true
# Bring the server back for part (b).
start_server "" || { bad "server failed to restart for part (b)"; finish "stress-client-signals"; }
SPID="$(server_pid)"

# --- (b) SIGTERM graceful shutdown ------------------------------------------------------------------
HLOGB="/tmp/koh-sig-b-$$.log"
pty_connect_host_bg /data/local/tmp/koh-sigb.key "$HLOGB" 30 ""
w=0; C2=""
while [ "$w" -lt 12 ]; do C2="$(other_pid "$SPID")"; [ -n "$C2" ] && break; w=$((w + 1)); sleep 1; done
[ -n "$C2" ] || { bad "client (b) never attached"; rm -f "$HLOGB"; finish "stress-client-signals"; }

adb $ADB_SERIAL shell "kill -TERM $C2" >/dev/null 2>&1 || true
gone=0; w=0
while [ "$w" -lt 8 ]; do [ -z "$(proc_state "$C2")" ] && { gone=1; break; }; w=$((w + 1)); sleep 1; done
[ "$gone" = 1 ] && ok "SIGTERM shut the client down cleanly (process exited)" || bad "client did not exit on SIGTERM"
[ -z "$(other_pid "$SPID")" ] && ok "no orphaned client process left behind" || bad "an orphaned client lingered after SIGTERM"
wait "${PTY_BG_PID:-0}" 2>/dev/null || true
rm -f "$HLOGB"

assert_no_crash "$(cat_dev "$SRV_LOG")" >/dev/null && ok "no panic server-side" || bad "server log shows a panic"
finish "stress-client-signals"
