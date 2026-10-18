#!/usr/bin/env bash
set -euo pipefail
python3 - <<'PY'

import os, re, select, subprocess, sys, time
P = None
BUF = b""
def spawn(cmd):
    global P, BUF
    P = subprocess.Popen(["ssh", "-tt", "-e", "none", "bench", cmd], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    BUF = b""
def expect(pat, t=120):
    global BUF
    if isinstance(pat, str):
        pat = pat.encode()
    end = time.time() + t
    while True:
        m = re.search(pat, BUF)
        if m:
            BUF = BUF[m.end():]
            return m
        r, _, _ = select.select([P.stdout], [], [], max(0, end - time.time()))
        if not r:
            sys.exit(f"timeout waiting for {pat!r}: {BUF[-600:]!r}")
        d = os.read(P.stdout.fileno(), 65536)
        if not d:
            sys.exit(f"eof waiting for {pat!r}: {BUF[-600:]!r}")
        BUF += d
def send(s):
    P.stdin.write(s.encode() if isinstance(s, str) else s)
    P.stdin.flush()
def finish(t=60):
    P.stdin.close()
    P.wait(timeout=t)

spawn("~/bin/ledger-shell")
expect(r"ledger> ")
send("open 2026\r")
expect(r"ledger\[2026\]> ")
send("balance ops:travel\r")
m = expect(rb"ops:travel\s+(-?[0-9]+\.[0-9]{2})")
open("answer.txt", "w").write(m.group(1).decode() + "\n")
expect(r"> ")
send("quit\r")
finish()
PY
