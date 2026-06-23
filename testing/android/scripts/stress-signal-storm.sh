#!/bin/sh
# Stress: signal storm. Repeatedly start a server and tear it down with SIGTERM / SIGINT, asserting
# each time it drains gracefully (logs the shutdown, closes the endpoint) and exits — leaving no
# orphaned process and never panicking. Exercises the server's signal-drain path under repetition.
set -eu
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
. "$HERE/stress-lib.sh"

require_device_or_skip
push_binary

ROUNDS="${KOH_STRESS_SIGNAL_ROUNDS:-$(scaled 12 40)}"
echo "Stress: signal storm — $ROUNDS start/drain rounds, alternating SIGTERM/SIGINT (level=$STRESS_LEVEL)"

drained=0
i=1
while [ "$i" -le "$ROUNDS" ]; do
  if [ $((i % 2)) -eq 0 ]; then SIG=INT; else SIG=TERM; fi
  if ! start_server ""; then bad "round $i: server did not start"; break; fi
  PID="$(server_pid)"
  adb $ADB_SERIAL shell "kill -$SIG $PID" >/dev/null 2>&1 || true

  # Wait for the process to actually exit (bounded).
  gone=0; j=0
  while [ "$j" -lt 8 ]; do
    [ -z "$(koh_pids)" ] && { gone=1; break; }
    j=$((j + 1)); sleep 1
  done
  SRV="$(cat_dev "$SRV_LOG")"

  if [ "$gone" != 1 ]; then bad "round $i (SIG$SIG): server did not exit"; stop_all_koh; break; fi
  if contains "$PANIC_RUST" "$SRV"; then bad "round $i: panic during shutdown"; break; fi
  if contains "draining" "$SRV" || contains "shutdown signal" "$SRV"; then
    drained=$((drained + 1))
  else
    bad "round $i (SIG$SIG): no graceful-drain log line"; printf '%s\n' "$SRV" | tail -3 | sed 's/^/      /'; break
  fi
  i=$((i + 1))
done

echo "  graceful drains: $drained/$ROUNDS"
[ "$drained" = "$ROUNDS" ] && ok "every SIGTERM/SIGINT drained gracefully and exited"
[ -z "$(koh_pids)" ] && ok "no orphaned koh process left behind" || bad "orphaned koh process(es): $(koh_pids)"

finish "stress-signal-storm"
