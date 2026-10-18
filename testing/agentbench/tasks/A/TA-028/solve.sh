#!/usr/bin/env bash
set -euo pipefail
ssh bench 'mkdir -p ~/www'
scp -qrp site bench:www/
