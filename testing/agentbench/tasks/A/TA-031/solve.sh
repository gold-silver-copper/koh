#!/usr/bin/env bash
set -euo pipefail
mkdir -p oom
ssh bench 'cd ~/logs && grep -rl "java.lang.OutOfMemoryError" . | tar -cf - -T -' | tar -C oom -xf -
