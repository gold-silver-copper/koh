#!/usr/bin/env bash
set -euo pipefail
ssh bench '~/bin/import-customers' 2>&1 >/dev/null | tail -1 > answer.txt || true
