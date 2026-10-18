#!/usr/bin/env bash
set -euo pipefail
ssh bench 'setsid nohup ~/bin/export-data > /dev/null 2>&1 < /dev/null & sleep 120' || true
until ssh bench 'while [ ! -e ~/exports/full-2026-10-17.bin ]; do sleep 0.5; done'; do :; done
scp -q bench:exports/full-2026-10-17.bin full.bin
