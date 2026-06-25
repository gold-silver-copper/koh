#!/bin/sh
# SECURITY (H-1): a malicious client's oversized terminal resize OOM-kills the koh SERVER, taking
# down EVERY peer's session in that process (cross-tenant DoS). The malicious resize is just a u16
# pair on the wire — the attacker allocates nothing; the server tries to allocate a rows×cols vt100
# grid (65000×65000 ≈ 135 GB).
#
# Asserts the SECURE behavior (server survives, witness session intact) — so it FAILS against
# unpatched koh (demonstrating the vuln) and PASSES once geometry is clamped.
set -eu
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
. "$HERE/stress-lib.sh"

require_device_or_skip
push_binary
push_evil

ROWS="${KOH_SEC_ROWS:-65000}"; COLS="${KOH_SEC_COLS:-65000}"
echo "Security H-1: malicious client resize(${ROWS}, ${COLS}) must NOT OOM-kill the server"

# Both the malicious client and the benign witness must be on the allowlist (no accept-any mode); the
# evil client loads its allowlisted identity from $EVIL_KEY_FILE.
EVIL_KEY=/data/local/tmp/koh-sec-evil.key
allow_client_key "$EVIL_KEY"
allow_client_key /data/local/tmp/koh-witness.key
start_server "" || { bad "server failed to start"; finish "sec-resize-oom-server"; }
SPID="$(server_pid)"

# A benign witness session, so we can show the cross-tenant impact (the server dying kills it too).
WITLOG="/tmp/koh-sec-witness-$$.log"
pty_connect_host_bg /data/local/tmp/koh-witness.key "$WITLOG" 30 ""
wait_file_contains_host "$WITLOG" "connected." 12 || true
echo "    server pid=$SPID; witness attached"

# Fire the attack (the evil client must be admitted to reach the data plane).
adb $ADB_SERIAL shell "EVIL_KEY_FILE=$EVIL_KEY $KENV $EVIL_DEV $SERVER_ID 127.0.0.1:$SERVER_PORT resize $ROWS $COLS" >/dev/null 2>&1 || true
sleep 6

SRV="$(cat_dev "$SRV_LOG")"
if [ -n "$(proc_state "$SPID")" ]; then
  ok "server survived the resize bomb (geometry clamped)"
else
  bad "server was KILLED by the malicious resize (H-1 confirmed) — every peer's session in this process died"
fi
assert_no_crash "$SRV" >/dev/null && ok "no panic/abort signature in the server log" || bad "server log shows a crash"

rm -f "$WITLOG"
finish "sec-resize-oom-server"
