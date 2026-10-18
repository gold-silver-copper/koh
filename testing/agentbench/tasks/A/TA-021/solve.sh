#!/usr/bin/env bash
set -euo pipefail
ssh bench 'sed -i "s/^max_connections = .*/max_connections = 1024/" ~/app/app.conf && mkdir -p ~/app/logs && ~/bin/app'
