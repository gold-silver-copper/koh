#!/usr/bin/env bash
set -euo pipefail
set +e
ssh bench '~/bin/migrate' > /dev/null 2> errors.txt
echo $? > status.txt
