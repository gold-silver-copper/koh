#!/bin/sh
# Stress: concurrent clients. Many distinct clients (different keys → different peers → different
# detachable sessions) hit one server at the same time. Exercises concurrent endpoint binds on the
# client side, concurrent accept/auth/attach on the server, and N simultaneous sessions. Asserts all
# handshakes succeed, the server survives, and memory stays bounded.
set -eu
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
. "$HERE/stress-lib.sh"

require_device_or_skip
push_binary

CLIENTS="${KOH_STRESS_CLIENTS:-$(scaled 8 24)}"
echo "Stress: concurrent clients — $CLIENTS simultaneous connects, distinct peers (level=$STRESS_LEVEL)"

# Each client uses its own key → its own node-id; all must be on the allowlist (no accept-any mode).
i=1
while [ "$i" -le "$CLIENTS" ]; do allow_client_key "/data/local/tmp/cc-$i.key"; i=$((i + 1)); done
start_server "" || { bad "server failed to start"; finish "stress-concurrent-clients"; }
SPID="$(server_pid)"
RSS0="$(rss_kb "$SPID")"

# Launch all clients at once, each to its own device log with its own key.
i=1
while [ "$i" -le "$CLIENTS" ]; do
  adb $ADB_SERIAL shell "rm -f /data/local/tmp/cc-$i.log" >/dev/null 2>&1 || true
  ( to 30 adb $ADB_SERIAL shell \
      "$KENV $DEVICE_BIN connect $SERVER_ID --direct 127.0.0.1:$SERVER_PORT --key-file /data/local/tmp/cc-$i.key >/data/local/tmp/cc-$i.log 2>&1" \
      >/dev/null 2>&1 || true ) &
  i=$((i + 1))
done
wait

connected=0
panics=0
i=1
while [ "$i" -le "$CLIENTS" ]; do
  L="$(cat_dev /data/local/tmp/cc-$i.log)"
  contains "connected." "$L" && connected=$((connected + 1))
  { contains "$PANIC_NDK" "$L" || contains "$PANIC_RUST" "$L"; } && panics=$((panics + 1))
  i=$((i + 1))
done

SPID2="$(server_pid)"
RSS1="$(rss_kb "${SPID2:-0}")"
echo "  handshakes: $connected/$CLIENTS   client panics: $panics   server RSS: ${RSS0}kB -> ${RSS1}kB"

[ "$connected" = "$CLIENTS" ] && ok "all $CLIENTS clients connected concurrently" || bad "$((CLIENTS - connected)) clients failed to connect"
[ "$panics" = 0 ] && ok "no client panicked (no ndk-context, no Rust panic)" || bad "$panics clients panicked"
[ -n "$SPID2" ] && ok "server survived $CLIENTS concurrent sessions" || bad "server died under concurrent load"
assert_no_crash "$(cat_dev "$SRV_LOG")" >/dev/null && ok "no panic in the server log" || bad "server log shows a panic"
LIMIT=$((RSS0 + 120000))
[ "$RSS1" -le "$LIMIT" ] && ok "server memory bounded (<= ${LIMIT}kB)" || bad "server RSS grew to ${RSS1}kB"

finish "stress-concurrent-clients"
