#!/usr/bin/env bash
set -euo pipefail
ssh bench '~/bin/start-farm && sleep 2'
ssh bench 'pkill -STOP -f "^farm-supervisor"; pkill -KILL -f "^farm-worker"; pkill -KILL -f "^farm-supervisor"; sleep 1; pkill -KILL -f "^farm-worker" || true'
