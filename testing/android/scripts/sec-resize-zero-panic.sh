#!/bin/sh
# SECURITY: a malicious client's (0, 0) resize must not panic the server's emulator (an unchecked
# rows-1 would overflow or index out of bounds). Asserts the server survives with no panic: geometry
# is clamped to at least MIN_DIM.
set -eu
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
. "$HERE/stress-lib.sh"

require_device_or_skip
push_binary
push_evil

echo "Security M-2: malicious client resize(0, 0) must NOT panic/crash the server"
# The malicious client must be on the allowlist (no accept-any mode) to reach the data plane.
EVIL_KEY=/data/local/tmp/koh-sec-evil.key
allow_client_key "$EVIL_KEY"
start_server "" || { bad "server failed to start"; finish "sec-resize-zero-panic"; }
SPID="$(server_pid)"

adb $ADB_SERIAL shell "EVIL_KEY_FILE=$EVIL_KEY $KENV $EVIL_DEV $SERVER_ID 127.0.0.1:$SERVER_PORT resize 0 0" >/dev/null 2>&1 || true
sleep 5

SRV="$(cat_dev "$SRV_LOG")"
[ -n "$(proc_state "$SPID")" ] && ok "server survived the zero-dimension resize (clamped to a valid minimum)" \
  || bad "server was CRASHED by a (0,0) resize (M-2 confirmed)"
printf '%s\n' "$SRV" | grep -q 'panicked' && bad "server PANICKED on the zero-dimension resize (M-2 confirmed)" \
  || ok "no panic in the server log"

finish "sec-resize-zero-panic"
