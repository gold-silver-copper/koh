#!/bin/sh
# Stress: wake-from-freeze PROACTIVE reconnect (the long-screen-off fix). A real system suspend
# pauses the *monotonic* clock that iroh's idle timer runs on, so after a long deep-sleep iroh can't
# tell the connection went stale and would hold it for up to its full ~5-minute idle timeout before
# giving up — a multi-minute hang on wake. The client guards against this with a WALL-CLOCK freeze
# detector: a >20s real-time gap between its (<=50ms-cadence) loop iterations is a resume-from-freeze
# fingerprint, so it drops the (almost certainly dead) connection and re-dials immediately.
#
# We SIGSTOP the client PAST that 20s threshold but WELL UNDER the 300s idle timeout. That window is
# the whole point: WITHOUT the fix the connection rides the freeze out on the SAME connection and the
# server logs NO reattach; WITH the fix the client reconnects within a couple of seconds of resume.
# So a pass REQUIRES the fix. We assert: a reattach is logged FAST (<=15s of resume), the client
# lands back in the SAME session (shell reused, not respawned), the client survives, nothing panics.
set -eu
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
. "$HERE/stress-lib.sh"

require_device_or_skip
push_binary

# > the 20s freeze-detector threshold, < the 300s idle timeout.
FREEZE="${KOH_STRESS_WAKE_FREEZE_SECS:-$(scaled 25 35)}"
SPAWNS="/data/local/tmp/koh-wake-spawns"
FLOOD="/data/local/tmp/koh-wake-shell.sh"
KEY="/data/local/tmp/koh-wake.key"
CLILOG="/tmp/koh-wake-cli-$$.log"
echo "Stress: wake-from-freeze reconnect — SIGSTOP the client ${FREEZE}s (> 20s detector, < 300s idle), then SIGCONT (level=$STRESS_LEVEL)"

# A recording session shell: appends a line per spawn then execs a real shell, so a REUSED session
# (a true reattach) leaves exactly ONE spawn line — a fresh session would add a second.
push_flood_script "$FLOOD" "echo spawned >> $SPAWNS ; exec /system/bin/sh"
adb $ADB_SERIAL shell "rm -f $SPAWNS" >/dev/null 2>&1 || true

start_server "--shell $FLOOD" || { bad "server failed to start"; finish "stress-client-wake-reconnect"; }
SPID="$(server_pid)"

# Hold the client open across attach + freeze + reconnect + observation; it self-quits afterwards.
pty_connect_host_bg "$KEY" "$CLILOG" $((FREEZE + 50)) ""

# Wait for the client to attach (a second koh pid appears) and the server to create the session.
w=0; CPID=""
while [ "$w" -lt 15 ]; do
  CPID="$(other_pid "$SPID")"
  [ -n "$CPID" ] && break
  w=$((w + 1)); sleep 1
done
[ -n "$CPID" ] || { bad "client never attached"; rm -f "$CLILOG"; finish "stress-client-wake-reconnect"; }
wait_file_contains "$SRV_LOG" "started a new session" 8 || true
echo "    client attached (server=$SPID, client=$CPID)"

# Freeze the client past the 20s detector threshold (still well under the 300s idle timeout, so
# without the fix the connection would simply ride this out — see the header).
adb $ADB_SERIAL shell "kill -STOP $CPID" >/dev/null 2>&1 || true
sleep 1
st="$(proc_state "$CPID")"
[ "$st" = T ] && ok "client is stopped (SIGSTOP'd, state=T) — simulating a long screen-off" || bad "client did not stop (state=$st)"

sleep "$FREEZE"

# Resume: the wall-clock freeze detector should fire on the first post-resume loop iteration and
# force an immediate re-dial + reattach.
adb $ADB_SERIAL shell "kill -CONT $CPID" >/dev/null 2>&1 || true

# THE KEY ASSERTION: the reconnect is FAST (<=15s), not after the ~5-min idle timeout. Without the
# fix the client rides out on the same connection and NO reattach is ever logged for this freeze.
if wait_file_contains "$SRV_LOG" "reattaching" 15; then
  ok "client proactively reconnected; server reattached within 15s of resume (the freeze detector fired)"
else
  bad "no reattach within 15s of resume — the client did not proactively reconnect (freeze detector did not fire)"
fi

sleep 2
st="$(proc_state "$CPID")"
case "$st" in
  R | S | D) ok "client survived the wake/reconnect (state=$st)" ;;
  "") bad "client died during the wake/reconnect" ;;
  *) bad "client in unexpected state after reconnect: $st" ;;
esac

SRV="$(cat_dev "$SRV_LOG")"
spawns="$(adb $ADB_SERIAL shell "wc -l < $SPAWNS 2>/dev/null || echo 0" | tr -d '\r' | awk '{print $1+0}')"
created="$(printf '%s\n' "$SRV" | grep -c 'started a new session' || true)"
echo "    shell spawns: $spawns   'started a new session': $created"
[ "$spawns" -eq 1 ] && ok "shell spawned exactly once and REUSED across the reconnect (session continuity)" || bad "shell spawned $spawns times — a new session was created, not reattached"
[ "$created" -eq 1 ] && ok "server created the session exactly once (the wake-reconnect reattached, not recreated)" || bad "server created the session $created times (expected 1)"
assert_no_crash "$SRV" >/dev/null && ok "no panic server-side" || bad "server log shows a panic"

rm -f "$CLILOG"
finish "stress-client-wake-reconnect"
