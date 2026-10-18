#!/usr/bin/env bash
set -euo pipefail
ssh bench '~/bin/start-db && until ~/bin/db-status; do sleep 0.3; done'
ssh bench 'p=$(cat ~/db/db.pid); kill -TERM $p; while kill -0 $p 2>/dev/null; do sleep 0.2; done'
