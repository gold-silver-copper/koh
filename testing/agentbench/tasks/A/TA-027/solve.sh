#!/usr/bin/env bash
set -euo pipefail
ssh bench '~/bin/snapshot'
scp -q 'bench:snap/*.snapshot' db.snapshot
