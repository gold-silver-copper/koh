#!/usr/bin/env bash
set -euo pipefail
ssh bench '~/bin/preflight >/dev/null 2>&1; echo $?' > answer.txt
