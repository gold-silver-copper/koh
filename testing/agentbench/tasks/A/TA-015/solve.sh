#!/usr/bin/env bash
set -euo pipefail
ssh bench '~/bin/deploy' | tail -1 > answer.txt || true
