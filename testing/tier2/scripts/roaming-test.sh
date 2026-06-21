#!/usr/bin/env bash
# Tier 2 roaming / connection-migration test (run on the HOST).
#
# Brings up the relay+server+client, starts a session driven by drive.exp inside the client
# container, and *mid-session* detaches the client from one network and attaches it to another
# (a fresh IP) — the closest automatable analogue of "Wi-Fi -> cellular". If the session
# resumes and re-syncs to the current screen, drive.exp prints the post-roam marker and exits 0.
#
# Requires Docker + Linux. NOT run by `cargo test`. Verify `iroh-relay --dev` against your
# installed iroh-relay (see README) before relying on the relay path.
set -euo pipefail
cd "$(dirname "$0")/.."

COMPOSE=(docker compose -f docker-compose.yml)

echo "==> building + starting relay/server/client"
"${COMPOSE[@]}" up --build -d

cleanup() { "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true; }
trap cleanup EXIT

client_cid() { "${COMPOSE[@]}" ps -q client; }

echo "==> starting server, capturing endpoint id"
"${COMPOSE[@]}" exec -T server sh -c '/scripts/run-server.sh > /tmp/server.log 2>&1 &' || true
sleep 4
SERVER_ID="$("${COMPOSE[@]}" exec -T server sh -c "grep -oE '[0-9a-f]{64}' /tmp/server.log | head -1")"
RELAY="http://relay:3340"
echo "    server id: ${SERVER_ID:-<not found>}"
[ -n "${SERVER_ID}" ] || { echo "FAIL: could not read server id from /tmp/server.log"; exit 1; }

echo "==> starting client driver (types ROAM_BEFORE, then waits)"
"${COMPOSE[@]}" exec -T client sh -c \
    "expect /scripts/drive.exp ${SERVER_ID} ${RELAY} > /tmp/drive.log 2>&1 &"

# Give drive.exp time to connect + confirm the pre-roam marker.
sleep 8

echo "==> ROAMING: moving the client to a new network (new IP) mid-session"
CID="$(client_cid)"
docker network disconnect tier2_clientnet "$CID"
docker network connect    tier2_clientnet2 "$CID"
echo "    client moved clientnet -> clientnet2"

# Let drive.exp attempt the post-roam command and finish.
sleep 14

echo "==> result:"
"${COMPOSE[@]}" exec -T client sh -c "cat /tmp/drive.log" || true
if "${COMPOSE[@]}" exec -T client sh -c "grep -q 'session resumed after roam' /tmp/drive.log"; then
    echo "PASS: QUIC migration resumed the session after the network move"
    exit 0
else
    echo "FAIL: session did not resume after the roam"
    exit 1
fi
