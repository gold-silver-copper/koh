#!/usr/bin/env bash
set -euo pipefail
ssh bench '~/bin/build 2>&1' | grep -o 'BLD-[0-9]*' | head -1 > answer.txt
