#!/bin/sh
# Test 1 (highest value): the Android DNS-panic regression.
#
# `koh serve` binds an iroh endpoint, and iroh constructs a DnsResolver at bind time. On a bare CLI
# (no Android app / JNI context — exactly what `adb shell` gives us) iroh's default resolver USED to
# panic with "ndk-context: android context was not initialized". koh pins an explicit nameserver on
# Android to avoid that. This test proves the endpoint binds and prints its ready banner — with no
# panic. (`koh id` would NOT do: it only prints the public key and never binds an endpoint.)
set -eu
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
. "$HERE/lib.sh"

require_device_or_skip
push_binary

echo "Test 1 — koh serve binds the iroh endpoint on Android (constructs DnsResolver) without panicking"
# serve blocks on accept(); run it briefly and assert on the banner it prints before blocking.
run_remote_blocking 12 "$DEVICE_BIN serve --allow-any --local --key-file /data/local/tmp/koh-server.key"
printf '%s\n' "$OUT" | grep -E 'koh server ready|endpoint id|connect|ndk-context|panic' | sed 's/^/    serve| /' | head -8

fail=0
if has_endpoint_id "$OUT"; then
  echo "  ok: server printed a 64-hex endpoint id → endpoint bound, DnsResolver constructed"
else
  echo "  FAIL: no endpoint id in serve output → the endpoint did not bind"; fail=1
fi
if assert_no_crash "$OUT"; then
  echo "  ok: no ndk-context panic, no Rust panic"
else
  fail=1
fi

if [ "$fail" = 0 ]; then echo "PASS: test-dns-resolver"; exit 0; else echo "FAIL: test-dns-resolver"; exit 1; fi
