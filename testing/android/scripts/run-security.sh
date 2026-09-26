#!/bin/sh
# Orchestrate the koh SECURITY tests on the emulator. Each sec-*.sh asserts the SECURE behavior, so
# the suite FAILS against unpatched koh (demonstrating the findings) and PASSES once they're fixed.
# OPT-IN + CI-safe exactly like the stress suite.
#
#   KOH_ANDROID_EMULATOR=1 sh testing/android/scripts/run-security.sh
set -eu
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
. "$HERE/lib.sh"

bootstrap_sdk_env
require_device_or_skip
echo "Device: ${ADB_SERIAL#-s }"
wait_for_boot || { echo "ERROR: device never finished booting" >&2; exit 1; }
# Rebuild what changed since the last run (a no-op when nothing did).
sh "$HERE/build-android.sh"
sh "$HERE/build-android.sh" evil
push_binary
echo

TESTS="sec-resize-oom-server sec-resize-zero-panic sec-key-perms sec-env-leak"
total=0; failed=0; failed_names=""; skipped=0; skipped_names=""
for t in $TESTS; do
  total=$((total + 1))
  echo "════════════════════════ $t ════════════════════════"
  run_test "$HERE/$t.sh"
  if [ "$TEST_RC" != 0 ]; then failed=$((failed + 1)); failed_names="$failed_names $t"
  elif [ "$TEST_SKIPPED" = 1 ]; then skipped=$((skipped + 1)); skipped_names="$skipped_names $t"; fi
  # Nothing a test left behind may reach the next one. Each test's own teardown already checked that
  # koh exits on SIGTERM; this only isolates the next test.
  adb $ADB_SERIAL shell "pkill -9 -f $DEVICE_BIN" >/dev/null 2>&1 || true
  echo
done

passed=$((total - failed - skipped))
echo "█████████████████████████████████████████████████████████"
echo "koh security tests: $passed/$total assert the secure behavior, $skipped skipped"
[ -n "$skipped_names" ] && echo "skipped (unverified):$skipped_names"
[ -n "$failed_names" ] && echo "demonstrating-a-vuln (or failing):$failed_names"
[ "$failed" = 0 ] || { echo "RESULT: FAIL (findings present or unverified)"; exit 1; }
echo "RESULT: PASS (all findings closed)"
