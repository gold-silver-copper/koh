#!/bin/sh
# Test 2: the KOH_DNS override path on Android.
#
# `discovery_dns_resolver()` honors KOH_DNS=<ip[:port]> on any platform. This exercises that branch
# on-device: with KOH_DNS set, `koh serve` must STILL bind the endpoint and print its banner with no
# ndk-context panic (proving the override constructs a valid resolver, not just the default pin).
set -eu
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
. "$HERE/lib.sh"

require_device_or_skip
push_binary

DNS="${KOH_DNS_TEST_VALUE:-1.1.1.1}"
echo "Test 2 — koh serve with KOH_DNS=$DNS binds cleanly on Android (override branch)"
run_remote_blocking 12 "KOH_DNS=$DNS $DEVICE_BIN serve --allow $(koh_id_of /data/local/tmp/koh-client.key) --local --key-file /data/local/tmp/koh-server.key"
printf '%s\n' "$OUT" | grep -E 'koh server ready|endpoint id|ndk-context|panic' | sed 's/^/    serve| /' | head -6

fail=0
if has_endpoint_id "$OUT"; then
  echo "  ok: endpoint bound with the KOH_DNS override in effect"
else
  echo "  FAIL: endpoint did not bind with KOH_DNS=$DNS"; fail=1
fi
if assert_no_crash "$OUT"; then
  echo "  ok: no ndk-context panic, no Rust panic"
else
  fail=1
fi

if [ "$fail" = 0 ]; then echo "PASS: test-dns-override"; exit 0; else echo "FAIL: test-dns-override"; exit 1; fi
