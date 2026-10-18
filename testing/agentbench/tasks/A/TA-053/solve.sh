#!/usr/bin/env bash
set -euo pipefail
ssh bench '~/bin/start-workers'
ssh bench 'sleep 3; kill $(ps -eo pid=,pcpu=,args= | grep "[w]orker-" | sort -k2 -nr | head -1 | awk "{print \$1}")'
