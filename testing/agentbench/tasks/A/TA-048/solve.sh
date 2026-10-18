#!/usr/bin/env bash
set -euo pipefail
ssh bench 'setsid nohup ~/bin/soak-test > ~/soak.out 2>&1 < /dev/null & sleep 120' || true
until ssh bench 'while ! grep -q "^soak: [0-9]* failures" ~/soak.out; do sleep 0.5; done'; do :; done
ssh bench 'cat ~/soak.out' | sed -n 's/^soak: \([0-9]*\) failures.*/\1/p' > answer.txt
