#!/usr/bin/env bash
set -euo pipefail
set +e
ssh bench '~/bin/ingest' > out.txt 2>&1
st=$?
{ echo "$st"; grep '^FATAL' out.txt; } > answer.txt
rm -f out.txt
