#!/bin/sh
# Stress: connection churn. One long-lived server; many rapid connect/disconnect cycles against it.
# Exercises the attach→detach lifecycle, the per-connection task spawn/teardown, and the detachable
# session machinery under repetition. Asserts the server stays alive and its memory stays bounded
# (no per-connection leak), every connect completes the handshake, and nothing panics.
set -eu
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
. "$HERE/stress-lib.sh"

require_device_or_skip
push_binary

CYCLES="${KOH_STRESS_CHURN_CYCLES:-$(scaled 30 150)}"
echo "Stress: connection churn — $CYCLES connect/disconnect cycles vs one server (level=$STRESS_LEVEL)"

start_server "" || { bad "server failed to start"; finish "stress-connection-churn"; }
SPID="$(server_pid)"
RSS0="$(rss_kb "$SPID")"
echo "  server pid=$SPID  baseline RSS=${RSS0}kB"

connected=0
i=1
while [ "$i" -le "$CYCLES" ]; do
  # Non-TTY connect: completes the handshake (prints "connected.") then exits at raw mode → detach.
  connect_once /data/local/tmp/koh-churn.key
  contains "connected." "$OUT" && connected=$((connected + 1))
  if contains "$PANIC_NDK" "$OUT" || contains "$PANIC_RUST" "$OUT"; then
    bad "client panicked on cycle $i"; break
  fi
  i=$((i + 1))
done

# Server must still be alive and not have ballooned.
SPID2="$(server_pid)"
RSS1="$(rss_kb "${SPID2:-0}")"
SRV="$(cat_dev "$SRV_LOG")"
echo "  handshakes completed: $connected/$CYCLES   server RSS: ${RSS0}kB -> ${RSS1}kB"

[ "$connected" = "$CYCLES" ] && ok "every cycle completed the handshake" || bad "$((CYCLES - connected)) cycles did not reach \"connected.\""
[ -n "$SPID2" ] && ok "server survived the churn (pid=$SPID2)" || bad "server died during the churn"
assert_no_crash "$SRV" >/dev/null && ok "no panic in the server log" || bad "server log shows a panic"
# Allow generous slack (alloc caching/scrollback) but catch a real per-connection leak.
LIMIT=$((RSS0 + 80000))
if [ "$RSS1" -le "$LIMIT" ]; then ok "server memory bounded (<= ${LIMIT}kB)"; else bad "server RSS grew to ${RSS1}kB (> ${LIMIT}kB) — possible per-connection leak"; fi

finish "stress-connection-churn"
