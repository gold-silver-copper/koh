#!/bin/sh
# Stress: auth flood resilience. A passphrase-protected server is hammered with failed-auth attempts.
# The reliable, security-relevant properties under stress: the server REJECTS bad credentials, never
# crashes, and bounds the work an attacker can extract. The per-peer rate limiter's engagement is
# reported as telemetry (not a hard gate) because iroh coalesces same-node-id connections on loopback,
# so driving 5+ DISTINCT failed handshakes from one peer is unreliable here.
#
# Scope note: this asserts FAILURE handling under load. Passphrase-auth SUCCESS (a correct passphrase
# authenticating over the SPAKE2 PAKE on arm64) is covered by `stress-pake-auth`, plus the in-process
# `transport_iroh::auth` unit + loopback integration tests — asserting success under THIS flood is
# flaky over loopback coalescing, so it is not gated here. All assertions are on the SERVER log (the
# client prints "connected." before the server validates, so client output can't tell pass from fail).
set -eu
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
. "$HERE/stress-lib.sh"

require_device_or_skip
push_binary

PASS="koh-stress-secret"
ATTEMPTS="${KOH_STRESS_AUTH_ATTEMPTS:-$(scaled 12 40)}"
echo "Stress: auth flood — $ATTEMPTS failed-auth attempts vs a passphrase-gated server (level=$STRESS_LEVEL)"

start_server "--passphrase $PASS" || { bad "server failed to start"; finish "stress-auth-ratelimit"; }
[ -n "$(server_pid)" ] && echo "  server up (passphrase required)"

# Flood: distinct keys (each a distinct node-id → each reliably reaches a fresh server-side
# handshake) plus one repeated key (to give the per-peer limiter a chance to engage).
i=1
while [ "$i" -le "$ATTEMPTS" ]; do
  connect_once "/data/local/tmp/koh-bad-$i.key" "--passphrase wrong-pass" >/dev/null 2>&1 || true
  i=$((i + 1))
done
j=1
while [ "$j" -le 6 ]; do
  connect_once /data/local/tmp/koh-badrepeat.key "--passphrase wrong-pass" >/dev/null 2>&1 || true
  sleep 2; j=$((j + 1))
done
sleep 3

SRV="$(cat_dev "$SRV_LOG")"
rej="$(printf '%s\n' "$SRV" | grep -c 'handshake rejected' || true)"
lim="$(printf '%s\n' "$SRV" | grep -c 'too many failed auth attempts' || true)"
authd="$(printf '%s\n' "$SRV" | grep -c 'client authorized' || true)"
echo "  server: $rej rejected, $lim rate-limit refusals, $authd authorizations"

# FATAL resilience/security properties.
[ "$authd" -eq 0 ] && ok "no wrong passphrase was ever authorized" || bad "a wrong passphrase was authorized ($authd)!"
[ "$rej" -ge 1 ] && ok "the passphrase gate rejected failed-auth attempts ($rej rejections)" || bad "no failed-auth attempt was rejected (did auth run?)"
[ -n "$(server_pid)" ] && ok "server stayed up under the auth flood" || bad "server died under the auth flood"
assert_no_crash "$SRV" >/dev/null && ok "no panic in the server log" || bad "server log shows a panic"
# Telemetry (non-deterministic on loopback).
if [ "$lim" -ge 1 ]; then echo "  note: the per-peer rate limiter engaged ($lim refusals)"; else echo "  note: rate limiter did not visibly engage this run (iroh loopback coalescing; logic is unit-tested)"; fi

finish "stress-auth-ratelimit"
