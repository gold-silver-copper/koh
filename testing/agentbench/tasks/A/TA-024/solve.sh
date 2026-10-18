#!/usr/bin/env bash
set -euo pipefail
ssh bench '~/bin/flash' < firmware.bin
