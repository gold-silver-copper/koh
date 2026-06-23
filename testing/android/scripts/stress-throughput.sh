#!/bin/sh
# Stress: throughput / large output. The server's session shell is a flood script that emits tens of
# thousands of lines the moment a client attaches, pushing a large volume through the full path:
# PTY -> server emulator (vt100 parse) -> SSP diff + DEFLATE + framing -> wire -> client. (Driving
# the flood from the SERVER side avoids having to forward typed input over adb's PTY, which is
# unreliable.) A sentinel written as the script's last line proves the whole flood was processed.
# Asserts: a client attaches, the flood completes, neither side panics, and server memory stays
# bounded under the load.
set -eu
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
. "$HERE/stress-lib.sh"

require_device_or_skip
push_binary

LINES="${KOH_STRESS_LINES:-$(scaled 20000 200000)}"
HOLD="${KOH_STRESS_TP_HOLD:-$(scaled 30 90)}"
SENT="/data/local/tmp/koh-tp-done"
FLOOD="/data/local/tmp/koh-tp-flood.sh"
CLILOG="/data/local/tmp/koh-tp-cli.log"
echo "Stress: throughput — server-side flood of $LINES lines to an attached client (level=$STRESS_LEVEL)"

# A "shell" that floods then writes the sentinel and exits (which ends the session cleanly).
push_flood_script "$FLOOD" "seq 1 $LINES; echo TP_DONE > $SENT"
adb $ADB_SERIAL shell "rm -f $SENT $CLILOG" >/dev/null 2>&1 || true

start_server "--shell $FLOOD" || { bad "server failed to start"; finish "stress-throughput"; }
SPID="$(server_pid)"
RSS0="$(rss_kb "$SPID")"

pty_connect_bg /data/local/tmp/koh-tp.key "$CLILOG" "$HOLD" ""
wait_file_contains "$CLILOG" "connected." 12 && ok "a client attached (the flood starts on attach)" || bad "the client never attached"

# Sample server RSS while the flood is in flight; wait for the sentinel (whole flood processed).
peak="$RSS0"; done_flood=0; k=0
while [ "$k" -lt "$HOLD" ]; do
  r="$(rss_kb "$SPID")"; [ "$r" -gt "$peak" ] && peak="$r"
  case "$(cat_dev "$SENT")" in *TP_DONE*) done_flood=1; break ;; esac
  k=$((k + 2)); sleep 2
done
wait "${PTY_BG_PID:-0}" 2>/dev/null || true

CLI="$(cat_dev "$CLILOG")"; SRV="$(cat_dev "$SRV_LOG")"
echo "  server RSS: ${RSS0}kB -> peak ${peak}kB   flood completed: $([ "$done_flood" = 1 ] && echo yes || echo no)"

[ "$done_flood" = 1 ] && ok "the full $LINES-line flood was processed end-to-end (sentinel written)" || bad "the flood did not complete within ${HOLD}s (no sentinel)"
assert_no_crash "$CLI" >/dev/null && ok "no panic on the client under the flood" || bad "client panicked under the flood"
assert_no_crash "$SRV" >/dev/null && ok "no panic on the server under the flood" || bad "server panicked under the flood"
LIMIT=$((RSS0 + 200000))
[ "$peak" -le "$LIMIT" ] && ok "server memory stayed bounded (peak ${peak}kB <= ${LIMIT}kB)" || bad "server RSS ballooned to ${peak}kB (> ${LIMIT}kB)"

finish "stress-throughput"
