#!/usr/bin/env bash
set -euo pipefail
ssh bench 'setsid nohup ~/bin/migrate-db > ~/migrate.out 2>&1 < /dev/null & sleep 120' || true
until ssh bench 'while ! grep -q "^migrate-db: done" ~/migrate.out; do sleep 0.5; done'; do :; done
