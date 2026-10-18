#!/usr/bin/env bash
set -euo pipefail
set +e
st=$(ssh bench '~/bin/cachedaemon > /dev/null; echo $?')
python3 -c "import signal,sys; print(signal.Signals($st - 128).name)" > answer.txt
