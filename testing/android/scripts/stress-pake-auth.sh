#!/bin/sh
# Stress: the PAKE passphrase handshake works on the real arm64 binary — BOTH accept and reject.
# The handshake is SPAKE2 over Ed25519 (curve25519-dalek crypto) plus mutual key confirmation, so
# this is the on-device proof that the cross-compiled PAKE actually authenticates a CORRECT
# passphrase and rejects a WRONG one (a runtime property cross-compilation alone can't verify, like
# the iroh/DNS panic the smoke suite catches). Asserts on the SERVER log — the client prints
# "connected." before the server validates, so client output can't tell pass from fail.
set -eu
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
. "$HERE/stress-lib.sh"

require_device_or_skip
push_binary

PASS="koh-pake-correct-secret"
echo "Stress: PAKE auth — a correct passphrase authenticates, a wrong one is rejected (level=$STRESS_LEVEL)"

start_server "--passphrase $PASS" || { bad "server failed to start"; finish "stress-pake-auth"; }
[ -n "$(server_pid)" ] && echo "  server up (passphrase required)"

# (1) A CORRECT passphrase MUST authenticate — this is the real proof the SPAKE2 exchange + mutual
#     key confirmation run correctly on arm64. Use a fresh key per attempt (distinct node-id ->
#     a fresh server-side handshake, avoiding iroh's loopback same-node-id coalescing), and retry a
#     couple of times so a coalesced/dropped first attempt doesn't flake the gate.
authed=0
k=1
while [ "$k" -le 3 ]; do
  connect_once "/data/local/tmp/koh-pake-good-$k.key" "--passphrase $PASS" >/dev/null 2>&1 || true
  if wait_file_contains "$SRV_LOG" "client authorized" 6; then authed=1; break; fi
  k=$((k + 1))
done
[ "$authed" -eq 1 ] \
  && ok "a CORRECT passphrase authenticated over the PAKE on-device (SPAKE2 + confirmation work on arm64)" \
  || bad "the correct passphrase never authenticated — the PAKE handshake may be broken on arm64"

# (2) A WRONG passphrase MUST be rejected and MUST NOT authenticate. Snapshot the authorization
#     count first so we can prove the wrong attempt added none.
before_auth="$(cat_dev "$SRV_LOG" | grep -c 'client authorized' || true)"
connect_once "/data/local/tmp/koh-pake-bad.key" "--passphrase totally-wrong-passphrase" >/dev/null 2>&1 || true
wait_file_contains "$SRV_LOG" "handshake rejected" 8 || true

SRV="$(cat_dev "$SRV_LOG")"
after_auth="$(printf '%s\n' "$SRV" | grep -c 'client authorized' || true)"
rej="$(printf '%s\n' "$SRV" | grep -c 'handshake rejected' || true)"
echo "  server: authorizations ${before_auth}->${after_auth}, $rej handshake rejection(s)"

[ "$rej" -ge 1 ] && ok "a WRONG passphrase was rejected by the PAKE ($rej rejection(s))" || bad "the wrong passphrase was not rejected (did the PAKE run?)"
[ "$after_auth" -eq "$before_auth" ] && ok "the wrong passphrase did NOT authenticate (no new authorization)" || bad "a wrong passphrase authenticated!"
[ -n "$(server_pid)" ] && ok "server stayed up through the PAKE auth exchanges" || bad "server died during the PAKE exchanges"
assert_no_crash "$SRV" >/dev/null && ok "no panic server-side" || bad "server log shows a panic"

finish "stress-pake-auth"
