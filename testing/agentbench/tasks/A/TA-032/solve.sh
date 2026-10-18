#!/usr/bin/env bash
set -euo pipefail
tar -C uploads -cf - . | ssh bench 'mkdir -p ~/inbox && tar -C ~/inbox -xf -'
