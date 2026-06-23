#!/bin/sh
# Stress: bad-network resilience — koh's reason to exist. Inject packet loss + latency on the
# device's loopback (where `--direct 127.0.0.1` traffic flows) and assert a session still survives
# end-to-end: QUIC rides out the loss, the flood completes, memory stays bounded, nothing panics.
#
# Best-effort: needs root (`adb root`, fine on google_apis) and `tc` (iproute2) on the image, which
# toybox-only builds may lack. Opt in with KOH_STRESS_NETEM=1; otherwise (or if tc/root is missing)
# it SKIPs cleanly. Full network-condition testing can instead run the server on the host and throttle
# the emulator's data network via the emulator console.
set -eu
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
. "$HERE/stress-lib.sh"

require_device_or_skip
push_binary

if [ "${KOH_STRESS_NETEM:-}" != "1" ]; then
  echo "SKIP: set KOH_STRESS_NETEM=1 to run the netem loss/latency test (needs root + tc)"
  exit 0
fi

LOSS="${KOH_STRESS_NETEM_LOSS:-20}"
DELAY="${KOH_STRESS_NETEM_DELAY:-80}"
echo "Stress: bad network — ${LOSS}% loss + ${DELAY}ms delay on loopback (level=$STRESS_LEVEL)"

adb $ADB_SERIAL root >/dev/null 2>&1 || true
adb $ADB_SERIAL wait-for-device >/dev/null 2>&1 || true
if ! adb $ADB_SERIAL shell 'command -v tc' >/dev/null 2>&1; then
  echo "SKIP: 'tc' (iproute2) not present on this system image — can't shape loopback"
  exit 0
fi

cleanup_tc() { adb $ADB_SERIAL shell "tc qdisc del dev lo root" >/dev/null 2>&1 || true; }
cleanup_tc   # clear any stale qdisc
if ! adb $ADB_SERIAL shell "tc qdisc add dev lo root netem loss ${LOSS}% delay ${DELAY}ms" >/dev/null 2>&1; then
  echo "SKIP: 'tc qdisc add … netem' failed (no permission / no netem module)"
  exit 0
fi
echo "    netem active on lo"

LINES="${KOH_STRESS_NETEM_LINES:-$(scaled 3000 15000)}"
SENT="/data/local/tmp/koh-netem-done"
FLOOD="/data/local/tmp/koh-netem-flood.sh"
CLILOG="/data/local/tmp/koh-netem-cli.log"
push_flood_script "$FLOOD" "seq 1 $LINES ; echo NETEM_DONE > $SENT"
adb $ADB_SERIAL shell "rm -f $SENT $CLILOG" >/dev/null 2>&1 || true

if ! start_server "--shell $FLOOD"; then bad "server failed to start under netem"; cleanup_tc; finish "stress-netem"; fi
SPID="$(server_pid)"; RSS0="$(rss_kb "$SPID")"

pty_connect_bg /data/local/tmp/koh-netem.key "$CLILOG" 60 ""
wait_file_contains "$CLILOG" "connected." 25 && ok "client connected over the lossy link" || bad "client never connected under loss"

peak="$RSS0"; done_flood=0; k=0
while [ "$k" -lt 60 ]; do
  r="$(rss_kb "$SPID")"; [ "$r" -gt "$peak" ] && peak="$r"
  case "$(cat_dev "$SENT")" in *NETEM_DONE*) done_flood=1; break ;; esac
  k=$((k + 3)); sleep 3
done
wait "${PTY_BG_PID:-0}" 2>/dev/null || true
SRV="$(cat_dev "$SRV_LOG")"; CLI="$(cat_dev "$CLILOG")"
cleanup_tc

echo "    flood completed under loss: $([ "$done_flood" = 1 ] && echo yes || echo no)   server RSS ${RSS0}->${peak}kB"
[ "$done_flood" = 1 ] && ok "the session survived ${LOSS}% loss and completed the flood end-to-end" || bad "the flood never completed under loss (QUIC should ride it out)"
assert_no_crash "$SRV" >/dev/null && ok "no panic server-side under loss" || bad "server panicked under loss"
assert_no_crash "$CLI" >/dev/null && ok "no panic client-side under loss" || bad "client panicked under loss"
[ "$peak" -le $((RSS0 + 200000)) ] && ok "server memory stayed bounded under loss" || bad "server RSS ballooned to ${peak}kB under loss"

finish "stress-netem"
