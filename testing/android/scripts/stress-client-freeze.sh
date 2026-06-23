#!/bin/sh
# Stress: client freeze → resume (the REAL screen-off scenario). A phone screen-off freezes the app,
# stopping its keepalives. koh's 5-min connection idle timeout exists so the session rides that out
# on the SAME connection. We SIGSTOP the client (not the server), hold well under the idle timeout,
# SIGCONT, and assert: the client was actually stopped, it survives, it stayed on the same connection
# (no detach/reconnect), and nothing panics.
set -eu
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
. "$HERE/stress-lib.sh"

require_device_or_skip
push_binary

FREEZE="${KOH_STRESS_FREEZE_SECS:-$(scaled 15 60)}"
CLILOG="/tmp/koh-freeze-cli-$$.log"
echo "Stress: client freeze → resume — SIGSTOP the client for ${FREEZE}s, then SIGCONT (level=$STRESS_LEVEL)"

start_server "" || { bad "server failed to start"; finish "stress-client-freeze"; }
SPID="$(server_pid)"

pty_connect_host_bg /data/local/tmp/koh-freeze.key "$CLILOG" $((FREEZE + 20)) ""
# Wait for the client to attach (a second koh pid appears).
w=0; CPID=""
while [ "$w" -lt 12 ]; do
  CPID="$(other_pid "$SPID")"
  [ -n "$CPID" ] && break
  w=$((w + 1)); sleep 1
done
[ -n "$CPID" ] || { bad "client never attached"; rm -f "$CLILOG"; stop_all_koh; finish "stress-client-freeze"; }
echo "    client attached (server=$SPID, client=$CPID)"

# Freeze the client.
adb $ADB_SERIAL shell "kill -STOP $CPID" >/dev/null 2>&1 || true
sleep 1
st="$(proc_state "$CPID")"
[ "$st" = T ] && ok "client is stopped (SIGSTOP'd, state=T) — simulating screen-off" || bad "client did not stop (state=$st)"

sleep "$FREEZE"   # frozen, well under the 300s idle timeout

# Resume the client.
adb $ADB_SERIAL shell "kill -CONT $CPID" >/dev/null 2>&1 || true
sleep 4
st="$(proc_state "$CPID")"

SRV="$(cat_dev "$SRV_LOG")"
case "$st" in
  R | S | D) ok "client resumed (state=$st) and is alive" ;;
  "") bad "client died during the freeze (should have ridden it out)" ;;
  *) bad "client in unexpected state after resume: $st" ;;
esac
# It must have stayed on the SAME connection — no detach / reattach happened server-side.
if printf '%s\n' "$SRV" | grep -qE 'client detached|reattaching'; then
  bad "the session detached/reconnected — it should have ridden out the freeze on the same connection"
else
  ok "session stayed on the same connection (no detach/reconnect) — rode out the freeze"
fi
assert_no_crash "$SRV" >/dev/null && ok "no panic server-side" || bad "server log shows a panic"

rm -f "$CLILOG"
finish "stress-client-freeze"
