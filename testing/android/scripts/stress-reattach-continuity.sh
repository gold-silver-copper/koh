#!/bin/sh
# Stress: detachable-session reattach continuity ("close the lid, reopen"). Disconnect then reconnect
# the same peer and prove it lands back in the SAME session with the SAME shell process — not a fresh
# one. The session shell records each spawn to a file then `exec`s a real shell; if the session is
# reused on reconnect (not recreated), the file has exactly ONE line.
set -eu
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
. "$HERE/stress-lib.sh"

require_device_or_skip
push_binary

SPAWNS="/data/local/tmp/koh-spawns"
FLOOD="/data/local/tmp/koh-reattach-shell.sh"
KEY="/data/local/tmp/koh-reattach.key"
echo "Stress: reattach continuity — disconnect then reconnect the same peer (level=$STRESS_LEVEL)"

# A session shell that records each spawn, then becomes a normal interactive shell (so it stays
# alive while detached and is REUSED on reattach).
push_flood_script "$FLOOD" "echo spawned >> $SPAWNS ; exec /system/bin/sh"
adb $ADB_SERIAL shell "rm -f $SPAWNS" >/dev/null 2>&1 || true

allow_client_key "$KEY"
start_server "--shell $FLOOD" || { bad "server failed to start"; finish "stress-reattach-continuity"; }

connect_a() {  # connect_a <host-log>; connects, holds briefly, quits cleanly
  pty_connect_host_bg "$KEY" "$1" 5 ""
  # wait for "connected." then for the client to finish (quit on hold-expiry)
  wait_file_contains_host "$1" "connected." 12 || true
  wait "${PTY_BG_PID:-0}" 2>/dev/null || true
}
# Host-side variant of wait_file_contains (the PTY stream is captured to a HOST file here).
wait_file_contains_host() { _j=0; while [ "$_j" -lt "$3" ]; do grep -aq "$2" "$1" 2>/dev/null && return 0; _j=$((_j+1)); sleep 1; done; return 1; }

# First connect: creates the session (1 spawn), then detaches on quit.
connect_a "/tmp/koh-reatt-1-$$.log"
wait_file_contains "$SRV_LOG" "client detached" 10 && echo "    first client detached (session retained)" || bad "server did not detach the first client"
sleep 2

# Second connect (same key): must reattach to the SAME session — no new spawn.
connect_a "/tmp/koh-reatt-2-$$.log"
sleep 2

SRV="$(cat_dev "$SRV_LOG")"
spawns="$(adb $ADB_SERIAL shell "wc -l < $SPAWNS 2>/dev/null || echo 0" | tr -d '\r' | awk '{print $1+0}')"
created="$(printf '%s\n' "$SRV" | grep -c 'started a new session' || true)"
reatt="$(printf '%s\n' "$SRV" | grep -c 'reattaching to this peer' || true)"
echo "    shell spawns: $spawns   'started a new session': $created   'reattaching': $reatt"

[ "$spawns" -eq 1 ] && ok "the shell was spawned exactly once and REUSED on reconnect (true continuity)" || bad "shell spawned $spawns times — the session was recreated, not reattached"
[ "$created" -eq 1 ] && ok "server created the session exactly once" || bad "server created the session $created times (expected 1)"
[ "$reatt" -ge 1 ] && ok "server logged a reattach on the second connect" || bad "server did not log a reattach"
assert_no_crash "$SRV" >/dev/null && ok "no panic server-side" || bad "server log shows a panic"

rm -f /tmp/koh-reatt-1-$$.log /tmp/koh-reatt-2-$$.log
finish "stress-reattach-continuity"
