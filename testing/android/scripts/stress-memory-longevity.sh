#!/bin/sh
# Stress: memory longevity / leak detection. The server's session shell floods output FOREVER (an
# infinite `yes`), driven server-side so no client typing is needed. While an attached client renders
# the unbounded stream, we sample the server's RSS over an extended run. A bounded emulator (fixed
# screen + capped scrollback) should make RSS PLATEAU quickly; a steady upward trend would betray a
# per-frame/per-byte leak. Asserts the session attaches, RSS plateaus and stays under a cap, and
# nothing panics.
set -eu
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
. "$HERE/stress-lib.sh"

require_device_or_skip
push_binary

DURATION="${KOH_STRESS_LONGEVITY_SECS:-$(scaled 40 150)}"
FLOOD="/data/local/tmp/koh-long-flood.sh"
CLILOG="/data/local/tmp/koh-long-cli.log"
echo "Stress: memory longevity — ${DURATION}s of unbounded server-side output (level=$STRESS_LEVEL)"

push_flood_script "$FLOOD" "exec yes koh-longevity-flood"
adb $ADB_SERIAL shell "rm -f $CLILOG" >/dev/null 2>&1 || true

start_server "--shell $FLOOD" || { bad "server failed to start"; finish "stress-memory-longevity"; }
SPID="$(server_pid)"

pty_connect_bg /data/local/tmp/koh-long.key "$CLILOG" "$((DURATION + 6))" ""
wait_file_contains "$CLILOG" "connected." 12 && ok "a client attached; flooding for ${DURATION}s" || bad "the client never attached"

samples=""; t=0
while [ "$t" -lt "$DURATION" ]; do
  sleep 5
  r="$(rss_kb "$SPID")"
  [ "$r" -gt 0 ] && samples="$samples $r"
  t=$((t + 5))
done
wait "${PTY_BG_PID:-0}" 2>/dev/null || true

SRV="$(cat_dev "$SRV_LOG")"
echo "  server RSS samples (kB):$samples"

verdict="$(printf '%s\n' "$samples" | awk '{
  if (NF < 3) { print "few"; exit }
  base=$2; max=0; for(i=2;i<=NF;i++) if($i>max) max=$i;          # baseline = 2nd sample (post-warmup)
  printf "%d %d %.2f", base, max, (base>0)?(max-base)/base:0;
}')"
base="$(echo "$verdict" | awk '{print $1}')"; peak="$(echo "$verdict" | awk '{print $2}')"; grow="$(echo "$verdict" | awk '{print $3}')"
echo "  baseline=${base}kB  peak=${peak}kB  steady-state growth=${grow}"

[ -n "$(server_pid)" ] && ok "server alive after ${DURATION}s of flooding" || bad "server died during the run"
assert_no_crash "$SRV" >/dev/null && ok "no panic over the run" || bad "server log shows a panic"
case "$verdict" in
  few) bad "not enough RSS samples to judge a plateau (run longer)" ;;
  *)
    if echo "$grow" | awk '{exit !($1 <= 0.40)}'; then ok "server RSS plateaued (steady-state growth ${grow} <= 0.40 — no leak)"; else bad "server RSS grew ${grow} over steady state — possible leak"; fi
    [ "$peak" -lt 250000 ] && ok "server RSS under the absolute cap (${peak}kB < 250000kB)" || bad "server RSS exceeded 250MB (${peak}kB)"
    ;;
esac

finish "stress-memory-longevity"
