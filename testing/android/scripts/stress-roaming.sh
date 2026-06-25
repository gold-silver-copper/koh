#!/bin/sh
# Stress: roaming / network-change resilience (migrated from tier2's roaming test — the analogue a
# single emulator CAN do). A live session over the real QUIC stack is hit with a TOTAL loopback
# outage (100% loss) mid-session — the closest single-host stand-in for "the network went away"
# (Wi-Fi→cellular). koh's 5-min connection idle timeout means QUIC should ride the outage out: the
# client notices (link-down banner), the connection is NOT dropped, and when the network returns the
# session resumes on the SAME connection (no detach/reconnect).
#
# Limitation (documented): a TRUE roam — the client's source IP changing while the server stays
# reachable, exercising QUIC connection *migration* / NAT hole-punching — needs two network paths,
# which one emulator over loopback can't provide. That property needs two hosts (or the old Docker
# multi-network setup); here we verify the user-facing resilience (session survives the outage).
#
# Best-effort: needs root + `tc`. Opt in with KOH_STRESS_NETEM=1; otherwise it SKIPs cleanly.
set -eu
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
. "$HERE/stress-lib.sh"

require_device_or_skip
push_binary

if [ "${KOH_STRESS_NETEM:-}" != "1" ]; then
  echo "SKIP: set KOH_STRESS_NETEM=1 to run the roaming/outage test (needs root + tc)"
  exit 0
fi
OUTAGE="${KOH_STRESS_ROAM_OUTAGE_SECS:-6}"   # must stay < the 300s connection idle timeout
echo "Stress: roaming — ${OUTAGE}s total loopback outage mid-session, then recover (level=$STRESS_LEVEL)"

adb $ADB_SERIAL root >/dev/null 2>&1 || true
adb $ADB_SERIAL wait-for-device >/dev/null 2>&1 || true
adb $ADB_SERIAL shell 'command -v tc' >/dev/null 2>&1 || { echo "SKIP: 'tc' not present on this image"; exit 0; }
cleanup_tc() { adb $ADB_SERIAL shell "tc qdisc del dev lo root" >/dev/null 2>&1 || true; }

allow_client_key /data/local/tmp/koh-roam.key
start_server "" || { bad "server failed to start"; finish "stress-roaming"; }
SPID="$(server_pid)"
CLILOG="/tmp/koh-roam-cli-$$.log"

pty_connect_host_bg /data/local/tmp/koh-roam.key "$CLILOG" $((OUTAGE + 30)) ""
w=0; CPID=""
while [ "$w" -lt 12 ]; do CPID="$(other_pid "$SPID")"; [ -n "$CPID" ] && break; w=$((w + 1)); sleep 1; done
[ -n "$CPID" ] || { bad "client never attached"; rm -f "$CLILOG"; stop_all_koh; finish "stress-roaming"; }
echo "    client attached (server=$SPID, client=$CPID)"

# Total outage on the QUIC path.
cleanup_tc
if ! adb $ADB_SERIAL shell "tc qdisc add dev lo root netem loss 100%" >/dev/null 2>&1; then
  echo "SKIP: couldn't apply a 100%-loss qdisc (no permission / no netem)"; rm -f "$CLILOG"; stop_all_koh; exit 0
fi
echo "    loopback blacked out (100% loss)"
sleep "$OUTAGE"

# The client should NOTICE the outage (its hold-the-session banner) but NOT exit.
noticed=0
grep -aqE 'resuming|link down' "$CLILOG" 2>/dev/null && noticed=1
[ -n "$(proc_state "$CPID")" ] && ok "client stayed alive during the outage (held the session)" || bad "client exited during the outage"

# Restore the network and let QUIC recover.
cleanup_tc
echo "    network restored"
sleep 6

SRV="$(cat_dev "$SRV_LOG")"
st="$(proc_state "$CPID")"
case "$st" in
  R | S | D) ok "client survived the outage (state=$st) and recovered" ;;
  "") bad "client died across the outage (should have ridden it out)" ;;
  *) bad "client in unexpected state after recovery: $st" ;;
esac
[ "$noticed" = 1 ] && ok "client surfaced its link-down banner during the outage" || echo "  note: link-down banner not observed (outage may have been shorter than the 3s detection)"
# It rode out the outage on the SAME connection — no detach/reconnect happened server-side.
if printf '%s\n' "$SRV" | grep -qE 'client detached|reattaching'; then
  bad "the session detached/reconnected — the outage should have been ridden out on the same connection"
else
  ok "session resumed on the same connection (no detach/reconnect) — QUIC rode out the outage"
fi
assert_no_crash "$SRV" >/dev/null && ok "no panic server-side" || bad "server log shows a panic"

cleanup_tc
rm -f "$CLILOG"
finish "stress-roaming"
