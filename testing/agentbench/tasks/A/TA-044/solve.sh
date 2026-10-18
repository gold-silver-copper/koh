#!/usr/bin/env bash
set -euo pipefail
ssh bench 'setsid nohup ~/bin/reindex > /dev/null 2>&1 < /dev/null & sleep 120' || true
until ssh bench 'while [ ! -e ~/reindex.done ]; do sleep 0.5; done'; do :; done
ssh bench 'cat ~/reindex.done' | awk '{print $2}' > answer.txt
