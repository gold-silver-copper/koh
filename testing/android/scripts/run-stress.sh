#!/bin/sh
# Orchestrate the full koh Android STRESS suite: guard → SDK env → build → push → run every stress
# test → tally. OPT-IN and CI-safe: with KOH_ANDROID_EMULATOR unset, or no device, it prints a SKIP
# and exits 0. Set KOH_STRESS_LEVEL=full for a heavy soak (longer/larger); default is `quick`.
#
#   KOH_ANDROID_EMULATOR=1 sh testing/android/scripts/run-stress.sh
#   KOH_ANDROID_EMULATOR=1 KOH_STRESS_LEVEL=full sh testing/android/scripts/run-stress.sh
set -eu
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
. "$HERE/lib.sh"

bootstrap_sdk_env
require_device_or_skip
echo "Device: ${ADB_SERIAL#-s }   level: ${KOH_STRESS_LEVEL:-quick}"
wait_for_boot || { echo "ERROR: device never finished booting" >&2; exit 1; }
push_binary
echo

# The last two (netem, relay-discovery) self-SKIP (exit 0) unless their opt-in env + prerequisites
# are present, so they're safe to always list here.
TESTS="stress-bind-storm stress-connection-churn stress-concurrent-clients stress-evil-peer stress-signal-storm stress-throughput stress-memory-longevity stress-reconnect-restart stress-client-freeze stress-client-wake-reconnect stress-reattach-continuity stress-client-signals stress-netem stress-roaming stress-relay-discovery"
total=0
failed=0
failed_names=""
for t in $TESTS; do
  total=$((total + 1))
  echo "════════════════════════ $t ════════════════════════"
  if sh "$HERE/$t.sh"; then :; else failed=$((failed + 1)); failed_names="$failed_names $t"; fi
  # Make sure nothing is left running between tests.
  adb $ADB_SERIAL shell "pkill -f $DEVICE_BIN" >/dev/null 2>&1 || true
  echo
done

passed=$((total - failed))
echo "█████████████████████████████████████████████████████████"
echo "koh Android stress suite: $passed/$total passed"
[ -n "$failed_names" ] && echo "failed:$failed_names"
[ "$failed" = 0 ] || { echo "RESULT: FAIL"; exit 1; }
echo "RESULT: PASS"
