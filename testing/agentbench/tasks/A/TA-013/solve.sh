#!/usr/bin/env bash
set -euo pipefail
ssh bench '~/bin/slowbuild' | sed -n 's/^artifact: \(build-.*\)$/\1/p' | tail -1 > answer.txt
