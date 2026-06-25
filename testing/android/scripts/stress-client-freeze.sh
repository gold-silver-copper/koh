#!/bin/sh
# Stress: SHORT client freeze → resume rides out on the SAME connection. A brief screen-off freezes
# the app and stops its keepalives; koh rides a short gap out on the existing connection — it is well
# under the 300s idle timeout AND, crucially, under the client's 20s wall-clock freeze detector,
# which on a LONGER freeze would instead force a proactive reconnect (that path is covered by
# stress-client-wake-reconnect). We SIGSTOP the client (not the server) for well under 20s, SIGCONT,
# and assert: it was actually stopped, it survives, it stayed on the SAME connection (no
# detach/reconnect), and nothing panics.
set -eu
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
. "$HERE/stress-lib.sh"

require_device_or_skip
push_binary

# Kept under the 20s freeze-detector threshold so the session rides out on the same connection
# (the longer freeze that trips proactive reconnect is exercised by stress-client-wake-reconnect).
FREEZE="${KOH_STRESS_FREEZE_SECS:-$(scaled 8 12)}"
CLILOG="/tmp/koh-freeze-cli-$$.log"
echo "Stress: client freeze → resume — SIGSTOP the client for ${FREEZE}s, then SIGCONT (level=$STRESS_LEVEL)"

allow_client_key /data/local/tmp/koh-freeze.key
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

sleep "$FREEZE"   # frozen, well under the 20s freeze detector (and the 300s idle timeout)

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
