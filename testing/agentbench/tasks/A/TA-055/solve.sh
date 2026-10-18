#!/usr/bin/env bash
set -euo pipefail
ssh bench '~/bin/start-proxy && sleep 1'
ssh bench 'sed -i "s/^upstream = .*/upstream = 10.0.0.9:8080/" ~/proxy/proxy.conf && kill -HUP $(cat ~/proxy/proxy.pid)'
ssh bench 'until grep -q "reloaded: upstream=10.0.0.9" ~/proxy/proxy.log; do sleep 0.2; done'
