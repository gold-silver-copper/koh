#!/usr/bin/env bash
set -euo pipefail
ssh bench '~/bin/package'
ssh bench 'tar -C ~ -cf - dist' | tar -xpf -
