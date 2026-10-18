#!/usr/bin/env bash
set -euo pipefail
ssh bench 'setsid nohup ~/bin/appserver > ~/appserver.log 2>&1 < /dev/null &'
ssh bench 'until grep -q "^ready" ~/appserver.log 2>/dev/null; do sleep 0.2; done; ~/bin/app-ping'
