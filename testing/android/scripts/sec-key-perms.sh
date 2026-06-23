#!/bin/sh
# SECURITY (M-1): the persistent secret identity key is written world-readable (default umask, ~0644)
# instead of 0600. The key IS the node's whole cryptographic identity → local impersonation. Asserts
# the SECURE behavior (mode 600) — fails against unpatched koh (644), passes once hardened.
set -eu
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
. "$HERE/stress-lib.sh"

require_device_or_skip
push_binary

KF=/data/local/tmp/koh-sec-id.key
echo "Security M-1: the persistent secret key must be written 0600 (not world-readable)"
adb $ADB_SERIAL shell "rm -f $KF; $DEVICE_BIN id --key-file $KF >/dev/null 2>&1"
mode="$(adb $ADB_SERIAL shell "stat -c '%a' $KF 2>/dev/null" | tr -d '\r')"
echo "    key file mode: $mode"

case "$mode" in
  600) ok "key file is 0600 (owner-only) — not readable by group/other" ;;
  "") bad "key file was not created — cannot check permissions" ;;
  *) bad "key file is mode $mode (group/other-readable) — M-1 confirmed: a local user can steal the node identity" ;;
esac

finish "sec-key-perms"
