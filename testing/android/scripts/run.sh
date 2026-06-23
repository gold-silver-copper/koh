#!/bin/sh
# Orchestrate the koh Android-emulator tests: guard → set up SDK env → build → push → run all tests.
#
# OPT-IN and CI-safe: with KOH_ANDROID_EMULATOR unset, or no emulator/device connected, this exits 0
# after printing a SKIP — it never fails a host build. Exits non-zero only if an actual test fails.
#
#   KOH_ANDROID_EMULATOR=1 sh testing/android/scripts/run.sh
set -eu
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
. "$HERE/lib.sh"

bootstrap_sdk_env
require_device_or_skip
echo "Device: ${ADB_SERIAL#-s }"
wait_for_boot || { echo "ERROR: device never finished booting" >&2; exit 1; }

# Build once and push once up front (each test also ensures these, idempotently).
push_binary
echo "Binary on device: $DEVICE_BIN"
echo

total=0
failed=0
for t in test-dns-resolver test-dns-override test-loopback-e2e; do
  total=$((total + 1))
  echo "──────────────────────── $t ────────────────────────"
  if sh "$HERE/$t.sh"; then :; else failed=$((failed + 1)); fi
  echo
done

passed=$((total - failed))
echo "════════════════════════════════════════════════════════"
echo "Android emulator tests: $passed/$total passed"
[ "$failed" = 0 ] || { echo "RESULT: FAIL"; exit 1; }
echo "RESULT: PASS"
