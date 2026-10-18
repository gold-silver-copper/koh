#!/usr/bin/env bash
set -euo pipefail
ssh bench '~/bin/buildinfo --json' | python3 -c 'import json,sys; print(json.load(sys.stdin)["source"]["commit"])' > answer.txt
