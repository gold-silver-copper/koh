#!/usr/bin/env bash
set -euo pipefail
ssh bench '~/bin/watch-build' > watch.out &
w=$!
until ssh bench '~/bin/trigger-build'; do sleep 0.5; done
wait $w
rm -f watch.out
