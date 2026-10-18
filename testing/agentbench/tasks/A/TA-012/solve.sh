#!/usr/bin/env bash
set -euo pipefail
ssh bench '~/bin/verify-archive 2>/dev/null' | grep -n 'checksum mismatch' | cut -d: -f1 > answer.txt
