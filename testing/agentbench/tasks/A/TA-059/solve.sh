#!/usr/bin/env bash
set -euo pipefail
ssh bench 'for c in disk mem net; do ~/bin/check-$c > /dev/null; echo "$c $?"; done' > health.txt
