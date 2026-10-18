#!/usr/bin/env bash
set -euo pipefail
ssh bench '~/bin/export'
ssh bench 'until [ -e ~/out/export.done ]; do sleep 0.3; done'
scp -q bench:out/export.csv export.csv
