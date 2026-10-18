#!/usr/bin/env bash
set -euo pipefail
ssh bench '~/bin/dump-config' | tr ';' '\n' | sed -n 's/^upstream_token=//p' > answer.txt
