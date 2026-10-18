#!/usr/bin/env bash
set -euo pipefail
ssh bench '~/bin/nightly'
ssh bench 'while pgrep -f "^nightly-worker" >/dev/null; do sleep 0.5; done'
scp -q bench:reports/batch-7731.txt report.txt
