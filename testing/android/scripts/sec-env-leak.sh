#!/bin/sh
# SECURITY (L-4): the server's $KOH_PASSPHRASE (the second-factor secret) is inherited verbatim into
# the spawned login shell's environment, so anyone who gets a shell can `echo $KOH_PASSPHRASE`. The
# session shell here records its own KOH_PASSPHRASE on spawn. Asserts the SECURE behavior (the
# passphrase is NOT in the shell's env) — fails against unpatched koh, passes once scrubbed.
set -eu
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
. "$HERE/stress-lib.sh"

require_device_or_skip
push_binary

SECRET="koh-sec-topsecret-$$"
LEAK=/data/local/tmp/koh-sec-leak
FLOOD=/data/local/tmp/koh-sec-envshell.sh
echo "Security L-4: the spawned shell must NOT inherit \$KOH_PASSPHRASE"

# A session shell that records its inherited KOH_PASSPHRASE, then becomes a normal shell.
push_flood_script "$FLOOD" "env | grep '^KOH_PASSPHRASE=' > $LEAK ; exec /system/bin/sh"
adb $ADB_SERIAL shell "rm -f $LEAK" >/dev/null 2>&1 || true

# Start the server with the passphrase via the env (the recommended path), and the recording shell.
adb $ADB_SERIAL shell "pkill -f $DEVICE_BIN" 2>/dev/null || true; sleep 1
adb $ADB_SERIAL shell "rm -f $SRV_LOG; KOH_PASSPHRASE=$SECRET nohup $DEVICE_BIN serve --allow-any --local --shell $FLOOD --key-file /data/local/tmp/koh-sec.key >$SRV_LOG 2>&1 &" >/dev/null
sleep 2
SERVER_ID="$(cat_dev "$SRV_LOG" | grep -oE '[0-9a-f]{64}' | head -1)"
SERVER_PORT="$(cat_dev "$SRV_LOG" | grep -- '--direct' | grep -oE ':[0-9]+' | tail -1 | tr -d ':')"
[ -n "$SERVER_PORT" ] || { bad "passphrase server did not start"; stop_all_koh; finish "sec-env-leak"; }

# Connect with the correct passphrase to spawn the session shell.
connect_once /data/local/tmp/koh-sec-cli.key "--passphrase $SECRET" >/dev/null 2>&1 || true
sleep 3

leaked="$(cat_dev "$LEAK")"
if printf '%s' "$leaked" | grep -q "$SECRET"; then
  bad "the passphrase LEAKED into the shell env (L-4 confirmed): $(printf '%s' "$leaked" | sed "s/$SECRET/<secret>/")"
else
  ok "the spawned shell's env contains no KOH_PASSPHRASE (scrubbed)"
fi

stop_all_koh
finish "sec-env-leak"
