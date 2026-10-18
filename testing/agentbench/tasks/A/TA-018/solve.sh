#!/usr/bin/env bash
set -euo pipefail
n=0
while :; do
  n=$((n + 1))
  if ssh bench '~/bin/flaky-test'; then break; fi
done
echo "$n" > answer.txt
