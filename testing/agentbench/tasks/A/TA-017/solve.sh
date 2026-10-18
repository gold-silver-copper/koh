#!/usr/bin/env bash
set -euo pipefail
ssh bench '~/bin/queue-worker' | while read -r line; do
  case $line in
    "job J-0417 done result="*) v=${line#*result=}; echo "${v%% *}" > answer.txt; break ;;
  esac
done || true
ssh bench 'for p in $(cat ~/run/worker.pids); do kill $p 2>/dev/null || true; done'
