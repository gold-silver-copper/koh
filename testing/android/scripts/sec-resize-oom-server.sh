#!/bin/sh
# SECURITY: a malicious client's oversized terminal resize must not OOM-kill the koh SERVER, which
# would take down EVERY peer's session in that process (cross-tenant DoS). The malicious resize is
# just a u16 pair on the wire — the attacker allocates nothing; an unclamped server would allocate a
# rows×cols grid (65000×65000 ≈ 135 GB).
#
# Asserts the server survives with the witness session intact and its memory bounded: geometry is
# clamped, and the frames a client never acknowledges share one screen and hold at most one of the
# largest size, so the clamped 1000x1000 cannot be held sixteen times over (~680 MB).
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
wait_attached /data/local/tmp/koh-witness.key 12 || bad "the witness session never attached"
echo "    server pid=$SPID; witness attached"

# Fire the attack (the evil client must be admitted to reach the data plane), sampling the server's
# memory while it runs.
RSS_LIMIT="${KOH_SEC_RSS_LIMIT_KB:-262144}"   # 256 MiB, as stress-evil-peer
( adb $ADB_SERIAL shell "EVIL_KEY_FILE=$EVIL_KEY $KENV $EVIL_DEV $SERVER_ID 127.0.0.1:$SERVER_PORT resize $ROWS $COLS" >/dev/null 2>&1 || true ) &
ATTACK_BG=$!
PEAK="$(peak_rss_kb "$SPID" 6)"
wait "$ATTACK_BG" 2>/dev/null || true

SRV="$(cat_dev "$SRV_LOG")"
[ "$(attach_count "$SRV" "$(koh_id_of "$EVIL_KEY")")" -ge 1 ] \
  && ok "the malicious client was admitted (its resizes reached the session)" \
  || bad "the malicious client was never admitted — the attack did not run"
if [ -n "$(proc_state "$SPID")" ]; then
  ok "server survived the resize bomb (geometry clamped)"
else
  bad "server was KILLED by the malicious resize (H-1 confirmed) — every peer's session in this process died"
fi
[ "$PEAK" -le "$RSS_LIMIT" ] \
  && ok "server memory stayed bounded during the attack (peak ${PEAK}kB <= ${RSS_LIMIT}kB)" \
  || bad "server RSS peaked at ${PEAK}kB (> ${RSS_LIMIT}kB): one client can make it hold many largest-size screens"
assert_no_crash "$SRV" >/dev/null && ok "no panic/abort signature in the server log" || bad "server log shows a crash"

rm -f "$WITLOG"
finish "sec-resize-oom-server"
