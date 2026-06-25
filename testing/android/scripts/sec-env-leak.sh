#!/bin/sh
# SECURITY (L-4): the server's $KOH_KEY_PASSPHRASE (the identity-key passphrase, supplied via the env
# for an unattended `koh serve`) must NOT be inherited by the spawned login shell — otherwise anyone
# who gets a shell could `echo $KOH_KEY_PASSPHRASE` and read the secret protecting the at-rest key.
# koh scrubs KOH_* from the child env before exec; this records the spawned shell's KOH_* env and
# asserts the secret is absent. Fails against unpatched koh, passes once scrubbed.
set -eu
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
. "$HERE/stress-lib.sh"

require_device_or_skip
push_binary

SECRET="koh-sec-topsecret-$$"
LEAK=/data/local/tmp/koh-sec-leak
FLOOD=/data/local/tmp/koh-sec-envshell.sh
echo "Security L-4: the spawned shell must NOT inherit \$KOH_KEY_PASSPHRASE"

# A session shell that records the KOH_* env it was spawned with, then becomes a normal shell.
push_flood_script "$FLOOD" "env | grep '^KOH_' > $LEAK ; exec /system/bin/sh"
adb $ADB_SERIAL shell "rm -f $LEAK" >/dev/null 2>&1 || true

# Allowlist the client, then start the server with its identity-key passphrase via the env (the
# recommended unattended path) and the recording shell. The server's key is created/opened under
# $SECRET (>= the enforced 8-char minimum); the client key uses the harness default ($KENV).
CLI_ID="$(koh_id_of /data/local/tmp/koh-sec-cli.key)"
adb $ADB_SERIAL shell "pkill -f $DEVICE_BIN" 2>/dev/null || true; sleep 1
adb $ADB_SERIAL shell "rm -f $SRV_LOG; KOH_KEY_PASSPHRASE=$SECRET KOH_KEY_NEW_PASSPHRASE=$SECRET nohup $DEVICE_BIN serve --allow $CLI_ID --local --shell $FLOOD --key-file /data/local/tmp/koh-sec.key >$SRV_LOG 2>&1 &" >/dev/null
sleep 2
SERVER_ID="$(cat_dev "$SRV_LOG" | grep -oE '[0-9a-f]{64}' | head -1)"
SERVER_PORT="$(cat_dev "$SRV_LOG" | grep -- '--direct' | grep -oE ':[0-9]+' | tail -1 | tr -d ':')"
[ -n "$SERVER_PORT" ] || { bad "the server did not start"; stop_all_koh; finish "sec-env-leak"; }

# Connect (allowlisted) to spawn the session shell; connect_once injects $KENV for the client key.
connect_once /data/local/tmp/koh-sec-cli.key >/dev/null 2>&1 || true
sleep 3

leaked="$(cat_dev "$LEAK")"
if printf '%s' "$leaked" | grep -q "$SECRET"; then
  bad "the key passphrase LEAKED into the shell env (L-4 confirmed): $(printf '%s' "$leaked" | sed "s/$SECRET/<secret>/")"
else
  ok "the spawned shell's env contains no KOH_KEY_PASSPHRASE (scrubbed)"
fi

stop_all_koh
finish "sec-env-leak"
