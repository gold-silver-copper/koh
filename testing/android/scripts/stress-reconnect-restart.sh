#!/bin/sh
# Stress: link-drop resilience (koh's marquee Android behavior). A live PTY session is established,
# then the SERVER is hard-killed out from under it — exactly what a phone freeze / network drop looks
# like to the client (keepalives stop, the link is NOT cleanly torn down). koh must NOT exit to the
# local shell: it rides out the outage, keeping the session and surfacing its "link down — resuming…"
# banner. We verify the client process SURVIVES the server death and that it drew the link-down
# banner. We don't wait for a full re-dial: on a hard kill that only follows the 300s idle timeout.
set -eu
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
. "$HERE/stress-lib.sh"

require_device_or_skip
push_binary

ROUNDS="${KOH_STRESS_RECONNECT_ROUNDS:-$(scaled 2 6)}"
HOSTLOG="/tmp/koh-rc-cli-$$.log"
echo "Stress: link-drop resilience — $ROUNDS round(s) of kill-server-under-a-live-client (level=$STRESS_LEVEL)"

survived=0
bannered=0
allow_client_key /data/local/tmp/koh-rc.key   # the reconnecting client must be on the allowlist
RC_ID="$(koh_id_of /data/local/tmp/koh-rc.key)"
r=1
while [ "$r" -le "$ROUNDS" ]; do
  echo "  round $r:"
  stop_all_koh
  start_server "" || { bad "round $r: server failed to start"; break; }
  SPID="$(server_pid)"   # only the server runs right now → this is its pid

  pty_connect_host_bg /data/local/tmp/koh-rc.key "$HOSTLOG" 40 ""
  # Wait for the server to attach the client's session (a running client process alone may still be
  # dialing), then give its first frame a moment to arrive.
  attached=0; w=0
  while [ "$w" -lt 12 ]; do
    [ "$(attach_count "$(cat_dev "$SRV_LOG")" "$RC_ID")" -ge 1 ] && { attached=1; break; }
    w=$((w + 1)); sleep 1
  done
  [ "$attached" = 1 ] || { bad "round $r: client never attached"; stop_all_koh; break; }
  sleep 1
  echo "    client attached (server pid=$SPID, koh procs=$(koh_count))"

  # Hard-kill ONLY the server; the client's link goes silent without a graceful close.
  adb $ADB_SERIAL shell "kill -9 $SPID" >/dev/null 2>&1 || true

  # Give the client time to notice and KEEP RUNNING. Its banner comes after 9s of silence (three
  # missed 3s heartbeats), so up to 12s after the kill.
  w=0; noticed=0
  while [ "$w" -lt 15 ]; do
    grep -aq 'link down' "$HOSTLOG" 2>/dev/null && { noticed=1; break; }
    w=$((w + 1)); sleep 1
  done

  if [ -n "$(koh_pids)" ]; then
    survived=$((survived + 1)); echo "    client still alive after the server died (rode out the drop, did not exit to shell)"
  else
    bad "round $r: client exited when the link dropped (should hold the session and keep trying)"
    stop_all_koh; break
  fi
  if [ "$noticed" = 1 ]; then
    bannered=$((bannered + 1)); echo "    client surfaced its link-down banner"
  else
    bad "round $r: the client never drew its link-down banner"
  fi

  stop_all_koh   # quit the client for the next round
  r=$((r + 1))
done

rm -f "$HOSTLOG"
echo "  rounds survived: $survived/$ROUNDS   (link-down banner observed in $bannered)"
[ "$survived" = "$ROUNDS" ] && ok "the client rode out every server death and stayed alive (mosh-style resilience)"

finish "stress-reconnect-restart"
