import os
import json


def read(path):
    try:
        with open(path, errors="replace") as f:
            return f.read()
    except OSError:
        return None


def readb(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError:
        return None


def alive(pid):
    try:
        with open(f"/proc/{int(pid)}/stat") as f:
            return f.read().rsplit(")", 1)[1].split()[0] not in ("Z", "X")
    except (OSError, ValueError, IndexError):
        return False


def fixture(name, side="remote/bin"):
    """The task's own copy of a fixture, loaded as a module (its main guarded)."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "setup", *side.split("/"), name)
    ns = {"__name__": "fixture", "__file__": path}
    with open(path) as f:
        exec(compile(f.read(), path, "exec"), ns)
    return ns


import glob
def expected(remote):
    table, skipped = {}, 0
    for p in sorted(glob.glob(os.path.join(remote, "data", "*.log"))):
        for line in open(p):
            if not line.strip():
                continue
            f = line.split()
            try:
                st = int(f[8])
                b = 0 if f[9] == "-" else int(f[9])
                if not (0 <= st < 65536 and b >= 0):
                    raise ValueError
            except (IndexError, ValueError):
                skipped += 1
                continue
            n, tb = table.get(st, (0, 0))
            table[st] = (n + 1, tb + b)
    rows = [["status", "requests", "bytes"]] + [[str(s), str(n), str(b)] for s, (n, b) in sorted(table.items())]
    return rows + [["skipped", str(skipped)]]
def check(local, remote):
    crate = os.path.join(remote, "crates", "logsum")
    if not os.path.exists(os.path.join(crate, "target", "release", "logsum")):
        return False, "no release build of logsum"
    got = read(os.path.join(remote, "out", "summary.txt"))
    if got is None:
        return False, "~/out/summary.txt missing"
    rows = [l.split() for l in got.splitlines() if l.strip()]
    want = expected(remote)
    return rows == want, "summary right" if rows == want else f"summary has {rows}, wanted {want}"
