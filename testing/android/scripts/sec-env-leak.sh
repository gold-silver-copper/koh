#!/bin/sh
# SECURITY: koh's own environment (KOH_*) configures koh, not the hosted program, and must NOT
# be inherited by the spawned login shell. koh scrubs KOH_* from the child env before exec; this
# starts the server with a KOH_* canary, records the spawned shell's environment, and asserts it has
# no KOH_* variable. The TERM koh sets proves the record is the session shell's.
set -eu
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
. "$HERE/stress-lib.sh"

require_device_or_skip
push_binary

SECRET="koh-sec-canary-$$"
LEAK=/data/local/tmp/koh-sec-leak
FLOOD=/data/local/tmp/koh-sec-envshell.sh
echo "Security L-4: the spawned shell must NOT inherit koh's KOH_* environment"

# A session shell that records the env it was spawned with, then becomes a normal shell.
push_flood_script "$FLOOD" "env > $LEAK ; exec /system/bin/sh"
adb $ADB_SERIAL shell "rm -f $LEAK" >/dev/null 2>&1 || true

# Allowlist the client, then start the server with a KOH_* canary in its env and the recording
# shell.
CLI_ID="$(koh_id_of /data/local/tmp/koh-sec-cli.key)"
adb $ADB_SERIAL shell "pkill -f $DEVICE_BIN" 2>/dev/null || true; sleep 1
adb $ADB_SERIAL shell "rm -f $SRV_LOG; KOH_SEC_CANARY=$SECRET nohup $DEVICE_BIN serve --allow $CLI_ID --local --shell $FLOOD --key-file /data/local/tmp/koh-sec.key >$SRV_LOG 2>&1 &" >/dev/null
sleep 2
SERVER_ID="$(cat_dev "$SRV_LOG" | grep -oE '[0-9a-f]{64}' | head -1)"
SERVER_PORT="$(cat_dev "$SRV_LOG" | grep -- '--direct' | grep -oE ':[0-9]+' | tail -1 | tr -d ':')"
[ -n "$SERVER_PORT" ] || { bad "the server did not start"; stop_all_koh; finish "sec-env-leak"; }

# Connect (allowlisted) to spawn the session shell; connect_once injects $KENV for the client key.
connect_once /data/local/tmp/koh-sec-cli.key >/dev/null 2>&1 || true
sleep 3

recorded="$(cat_dev "$LEAK")"
leaked="$(printf '%s\n' "$recorded" | grep '^KOH_' || true)"
if ! printf '%s\n' "$recorded" | grep -q '^TERM='; then
  bad "the session shell never recorded its environment (did the session start?)"
elif [ -n "$leaked" ]; then
  bad "a KOH_* variable LEAKED into the shell env (L-4): $(printf '%s' "$leaked" | sed "s/$SECRET/<canary>/")"
else
  ok "the spawned shell's env contains no KOH_* variable, the canary included (scrubbed)"
fi

stop_all_koh
finish "sec-env-leak"
