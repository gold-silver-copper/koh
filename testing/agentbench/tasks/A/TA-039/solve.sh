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

spawn("~/bin/dbshell")
expect(r"shop=> ")
send("select c.name from customers c join orders o on o.customer_id = c.id\r")
expect(r"shop-> ")
send("where o.placed like '2025-%' group by c.id order by sum(o.amount) desc limit 1;\r")
m = expect(rb"\r\n ([A-Z][^\r\n|]*?) *\r\n\(1 row\)")
open("answer.txt", "w").write(m.group(1).decode().strip() + "\n")
send("\\q\r")
finish()
PY
