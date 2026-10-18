#!/usr/bin/env bash
set -euo pipefail
ssh bench 'bash -s' <<'REMOTE'
set -e
rm -rf ~/src/ledger-retry
git clone -q ~/git/ledger-retry.git ~/src/ledger-retry
cd ~/src/ledger-retry
git checkout -q feature/retry
git rebase main >/dev/null 2>&1 || true
cat > retry.py <<'PY'
"""Retry a call a few times."""
import time


def retry(fn, tries=3, exceptions=(Exception,), delay=0.0, sleep=time.sleep):
    """Call fn until it succeeds, at most `tries` times; re-raise the last error.

    Only the given exception types are retried; others propagate at once.
    Between tries, wait `delay` seconds, doubling each time.
    """
    last = None
    for i in range(tries):
        try:
            return fn()
        except exceptions as e:
            last = e
            if i + 1 < tries and delay:
                sleep(delay * 2 ** i)
    raise last
PY
python3 - <<'PY'
import re
t = open("test_retry.py").read()
t = re.sub(r"<<<<<<< .*?\n(.*?)=======\n(.*?)>>>>>>> .*?\n", lambda m: m.group(1) + m.group(2), t, flags=re.S)
t = t.replace("attempts=4", "tries=4")
open("test_retry.py", "w").write(t)
PY
python3 -m unittest -q
git add retry.py test_retry.py
GIT_EDITOR=true git rebase --continue >/dev/null
git push -q -f origin feature/retry
REMOTE
