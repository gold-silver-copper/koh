#!/usr/bin/env bash
set -euo pipefail
ssh bench '~/bin/fetch-all' | python3 -c '
import re, sys
out = []
for line in sys.stdin.read().split("\n"):
    last = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", line.split("\r")[-1]).strip()
    m = re.match(r"(\S+) FAILED \(", last)
    if m:
        out.append(m.group(1))
print("\n".join(sorted(out)))
' > failed.txt
