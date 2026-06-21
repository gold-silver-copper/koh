#!/usr/bin/env bash
# Start rmosh-server inside the server container, pointed at the self-hosted relay.
# Prints the endpoint id (capture it for the client).
set -euo pipefail

RELAY="${RMOSH_RELAY_URL:?set RMOSH_RELAY_URL}"
ALLOW="${RMOSH_ALLOW:-any}"

args=(--relay-url "$RELAY" --key-file /tmp/server.key)
if [ "$ALLOW" = "any" ]; then
    args+=(--allow-any)
else
    args+=(--allow "$ALLOW")
fi

echo "starting: rmosh-server ${args[*]}"
exec rmosh-server "${args[@]}"
