#!/bin/sh
# Test 3: on-device loopback p2p (server + client both on the emulator, no network).
#
# Starts `koh serve --local` detached on the device, scrapes its endpoint id + UDP port, then dials
# it with `koh connect ... --direct 127.0.0.1:<port>`. BOTH sides bind their own iroh endpoint (so
# both exercise the Android DnsResolver path), and the client must complete the handshake and print
# "connected." over loopback QUIC. Because `adb shell` provides no TTY, the client then fails at
# entering raw mode — that's expected and ignored; reaching "connected." proves the p2p path works.
set -eu
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
. "$HERE/lib.sh"

require_device_or_skip
push_binary
kill_remote_koh

LOG=/data/local/tmp/koh-server.log
echo "Test 3 — on-device loopback: serve + connect over --direct 127.0.0.1"
adb_ shell "rm -f $LOG; nohup $DEVICE_BIN serve --allow-any --local --key-file /data/local/tmp/koh-server.key >$LOG 2>&1 &" >/dev/null

# Wait for the server to bind and write its banner.
SRV=""
i=0
while [ $i -lt 20 ]; do
  SRV="$(adb_ shell cat "$LOG" 2>/dev/null | tr -d '\r')"
  has_endpoint_id "$SRV" && break
  i=$((i + 1)); sleep 1
done

ID="$(printf '%s' "$SRV" | grep -oE '[0-9a-f]{64}' | head -1)"
PORT="$(printf '%s' "$SRV" | grep -- '--direct' | grep -oE ':[0-9]+' | tail -1 | tr -d ':')"
[ -n "$PORT" ] || PORT="$(printf '%s' "$SRV" | grep -oE ':[0-9]{2,5}' | tail -1 | tr -d ':')"

fail=0
if [ -z "$ID" ] || [ -z "$PORT" ]; then
  echo "  FAIL: could not read server id/port from $LOG"
  printf '%s\n' "$SRV" | sed 's/^/    serve| /' | head -10
  kill_remote_koh
  echo "FAIL: test-loopback-e2e"; exit 1
fi
if ! assert_no_crash "$SRV"; then kill_remote_koh; echo "FAIL: test-loopback-e2e (server crashed)"; exit 1; fi
echo "  server up: id=${ID%??????????????????????????????????????????????????????????}… port=$PORT"

# Dial over loopback. No TTY here, so the client prints "connected." then errors at raw mode — fine.
run_remote "$DEVICE_BIN connect $ID --direct 127.0.0.1:$PORT --key-file /data/local/tmp/koh-client.key --predict never"
printf '%s\n' "$OUT" | grep -E 'connecting to|connected|ndk-context|panic|raw mode' | sed 's/^/    connect| /' | head -8
kill_remote_koh

if contains "connected." "$OUT"; then
  echo "  ok: client completed the handshake over loopback (p2p works on-device)"
else
  echo "  FAIL: client never reached \"connected.\" (loopback connect did not establish)"; fail=1
fi
if assert_no_crash "$OUT"; then
  echo "  ok: no ndk-context panic, no Rust panic on the client side either"
else
  fail=1
fi

if [ "$fail" = 0 ]; then echo "PASS: test-loopback-e2e"; exit 0; else echo "FAIL: test-loopback-e2e"; exit 1; fi
