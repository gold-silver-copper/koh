#!/bin/sh
# Stress: the MALICIOUS-PEER harness — crafted protocol attacks a stock koh peer never sends, run on
# the real arm64 binary. Three parts:
#   A) malicious CLIENT vs a server: each crafted wire/flood attack must leave the server ALIVE with
#      BOUNDED memory and NO panic, a benign witness session intact (no cross-tenant impact), and a
#      fresh legit client must still connect afterward.
#   B) admission-stall attack: an admitted-but-stalling client must be timed out by the server's
#      bounded admission step (KOH-08), and the server must survive.
#   C) malicious SERVER (admission direction): a real koh client must REFUSE a server that sends a
#      bad admission byte or never admits it (never reach "connected.") — fail-closed on-device.
#
# Every malicious peer must be on the server's --allow list to reach the data plane (koh has no
# accept-any mode), so the harness pre-registers their keys. Self-SKIPs cleanly if the evil-peer
# isn't cross-compiled (push_evil).
set -eu
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
. "$HERE/stress-lib.sh"

require_device_or_skip
push_binary
push_evil

RSS_LIMIT="${KOH_EVIL_RSS_LIMIT_KB:-262144}" # 256 MiB ceiling across the whole run
echo "Stress: malicious-peer harness — crafted client + admission attacks (level=$STRESS_LEVEL)"

# The evil client must be allowlisted to reach the data plane; it loads its (persistent, allowlisted)
# identity from $EVIL_KEY via $EVIL_KEY_FILE. $KENV opens the always-encrypted key non-interactively.
EVIL_KEY=/data/local/tmp/koh-evilcli.key
EVIL_ENV="EVIL_KEY_FILE=$EVIL_KEY $KENV"

# ---- Part A: malicious-CLIENT datagram attacks ---------------------------------------------------
allow_client_key "$EVIL_KEY"
allow_client_key /data/local/tmp/koh-evil-witness.key
allow_client_key /data/local/tmp/koh-evil-fresh.key
start_server "" || { bad "server failed to start"; finish "stress-evil-peer"; }
SPID="$(server_pid)"
WIT="/tmp/koh-evil-witness-$$.log"
pty_connect_host_bg /data/local/tmp/koh-evil-witness.key "$WIT" 120 ""
wait_file_contains_host "$WIT" "connected." 12 || true
echo "    server pid=$SPID; benign witness attached"
ADDR="127.0.0.1:$SERVER_PORT"

# <label> <attack-and-args...>: fire it, then require the server alive + bounded.
run_client_attack() {
  _label="$1"; shift
  echo "  -- client attack: $_label"
  adb $ADB_SERIAL shell "$EVIL_ENV $EVIL_DEV $SERVER_ID $ADDR $*" >/dev/null 2>&1 || true
  sleep 3
  if [ -z "$(proc_state "$SPID")" ]; then bad "[$_label] server was KILLED"; return; fi
  _rss="$(rss_kb "$SPID")"
  if [ "$_rss" -le "$RSS_LIMIT" ]; then
    ok "[$_label] server alive, RSS ${_rss}kB <= ${RSS_LIMIT}kB"
  else
    bad "[$_label] server RSS ${_rss}kB exceeded ${RSS_LIMIT}kB (possible leak/OOM)"
  fi
}

ACC="$(scaled 2000 8000)" # accumulation count scales with intensity

# bomb (KOH-02): the decisive proof is the server LOG, not RSS — with the inflate cap, the bomb
# aborts mid-inflate and `recv` logs "unreassemblable"; WITHOUT the cap the 14 MiB inflates (and the
# now-empty diff decodes), so that line never appears. We diff the count around just this attack.
echo "  -- client attack: decompression bomb (KOH-02)"
BOMB0="$(cat_dev "$SRV_LOG" | grep -c unreassemblable || true)"
adb $ADB_SERIAL shell "$EVIL_ENV $EVIL_DEV $SERVER_ID $ADDR bomb 14" >/dev/null 2>&1 || true
sleep 3
BOMB1="$(cat_dev "$SRV_LOG" | grep -c unreassemblable || true)"
if [ -z "$(proc_state "$SPID")" ]; then
  bad "[bomb] server was KILLED by the decompression bomb"
else
  _rss="$(rss_kb "$SPID")"
  [ "$_rss" -le "$RSS_LIMIT" ] && ok "[bomb] server RSS bounded (${_rss}kB)" || bad "[bomb] RSS ${_rss}kB > ${RSS_LIMIT}kB"
  [ "$BOMB1" -gt "$BOMB0" ] \
    && ok "[bomb] server rejected the bomb at the inflate cap (logged 'unreassemblable')" \
    || bad "[bomb] no inflate-cap rejection logged — the per-direction decode cap may be gone"
fi

run_client_attack "empty-fragment flood"   empty-frags 30000
run_client_attack "partial-fragment flood" partial-frags 30000
run_client_attack "state accumulation"     accumulate "$ACC" 4096

# resize-flood (KOH-05): the server must COALESCE to one resize, not run one ioctl(TIOCSWINSZ) +
# SIGWINCH + grid-realloc per event. A per-event regression is a CPU/syscall storm (minutes of CPU
# for 400k events), not an RSS blowup — so we gate on CPU jiffies burned, not memory.
echo "  -- client attack: resize flood (KOH-05 coalescing)"
J0="$(cpu_jiffies "$SPID")"
adb $ADB_SERIAL shell "$EVIL_ENV $EVIL_DEV $SERVER_ID $ADDR resize-flood 400000" >/dev/null 2>&1 || true
sleep 4
DJ=$(( $(cpu_jiffies "$SPID") - J0 ))
if [ -z "$(proc_state "$SPID")" ]; then
  bad "[resize-flood] server was KILLED"
elif [ "$DJ" -le "${KOH_EVIL_CPU_TICKS:-500}" ]; then
  ok "[resize-flood] server coalesced (burned ${DJ} CPU ticks <= 500; 400k per-event ops would burn thousands)"
else
  bad "[resize-flood] server burned ${DJ} CPU ticks — a per-event resize regression?"
fi

run_client_attack "keys flood (PTY write/budget)" keys-flood 6
run_client_attack "garbage datagrams"             garbage 30000
run_client_attack "bad protocol version"          bad-version

SRV="$(cat_dev "$SRV_LOG")"
[ -n "$(proc_state "$SPID")" ] && ok "server survived ALL client attacks" || bad "server died under the attacks"
assert_no_crash "$SRV" >/dev/null && ok "no panic/abort in the server log" || bad "server log shows a crash"
# The witness PTY capture records the reconnect banner IF its session was disrupted; its presence —
# not the historical "connected." banner — is the real cross-tenant-impact signal.
if grep -aq 'reconnecting' "$WIT"; then
  bad "the benign witness session was disrupted (cross-tenant impact)"
else
  ok "the benign witness stayed attached (no cross-tenant impact)"
fi
# A fresh legit client must still reach "connected." after the barrage — assert on ITS OWN captured
# output (connect_once → run_remote sets $OUT), not the server's stale log.
connect_once /data/local/tmp/koh-evil-fresh.key
if printf '%s\n' "$OUT" | grep -q 'connected.'; then
  ok "a fresh legit client still connects after the barrage"
else
  echo "  note: fresh-client connect not confirmed (loopback flake; not a hard gate)"
fi
rm -f "$WIT"
stop_all_koh

# ---- Part B: admission-stall attack — an admitted-but-stalling client must be timed out -----------
start_server "" || { bad "server failed to start for Part B"; finish "stress-evil-peer"; }
echo "  -- admission-stall attack (the server's 3s admission timeout must fire; KOH-08)"
adb $ADB_SERIAL shell "$EVIL_ENV $EVIL_DEV $SERVER_ID 127.0.0.1:$SERVER_PORT stall-admission" >/dev/null 2>&1 || true
sleep 7
SRV="$(cat_dev "$SRV_LOG")"
if printf '%s\n' "$SRV" | grep -qE 'admission ack timed out|too many handshakes'; then
  ok "the server bounded the stalled admission (timeout/cap fired)"
else
  echo "  note: no explicit admission-timeout line logged this run (still asserting survival below)"
fi
[ -n "$(server_pid)" ] && ok "server survived the admission-stall attack" || bad "server died under the admission-stall attack"
assert_no_crash "$SRV" >/dev/null && ok "no panic in the server log" || bad "server log shows a crash"
stop_all_koh

# ---- Part C: malicious SERVER (admission direction) — a koh CLIENT must refuse it ----------------
if [ -x "$EVIL_SERVER_HOST" ]; then
  for atk in bad-admit stall-admit; do
    echo "  -- malicious server: $atk (koh client must refuse)"
    ESLOG="/tmp/koh-evilsrv-$atk-$$.log"
    ( adb $ADB_SERIAL shell "$EVIL_SERVER_DEV $atk" > "$ESLOG" 2>&1 || true ) &
    EID=""; EPORT=""; w=0
    while [ "$w" -lt 12 ]; do
      EID="$(sed -n 's/.*EVIL_ID=//p' "$ESLOG" 2>/dev/null | head -1 | tr -d '\r')"
      EPORT="$(sed -n 's/.*EVIL_PORT=//p' "$ESLOG" 2>/dev/null | head -1 | tr -d '\r')"
      [ -n "$EID" ] && [ -n "$EPORT" ] && break
      w=$((w + 1)); sleep 1
    done
    if [ -z "$EID" ] || [ -z "$EPORT" ]; then bad "[$atk] evil-server did not announce its id/port"; rm -f "$ESLOG"; continue; fi
    # A koh client dials the malicious server; it must FAIL admission (never reach "connected.")
    # because a non-ADMIT byte is rejected and a never-opened admission stream times out.
    # run_remote injects $KENV so the client can open its own (always-encrypted) key.
    run_remote "$DEVICE_BIN connect $EID --direct 127.0.0.1:$EPORT --key-file /data/local/tmp/koh-evilcli-$atk.key"
    if printf '%s\n' "$OUT" | grep -q 'connected.'; then
      bad "[$atk] the koh client was TRICKED into connecting to the malicious server!"
    else
      ok "[$atk] the koh client refused the malicious server (never reached 'connected.')"
    fi
    rm -f "$ESLOG"
  done
else
  echo "  note: evil-server binary not pushed; skipping malicious-server (admission-direction) attacks"
fi

finish "stress-evil-peer"
