#!/usr/bin/env bash
set -euo pipefail
ssh bench 'cd ~/work/app && ./configure --prefix="$HOME/opt/app"'
