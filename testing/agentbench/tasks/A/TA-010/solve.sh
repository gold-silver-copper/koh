#!/usr/bin/env bash
set -euo pipefail
ssh bench '~/bin/replay' | head -1 | awk '{print $2}' > answer.txt
