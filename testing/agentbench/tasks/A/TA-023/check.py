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


import hashlib
def check(local, remote):
    data = readb(os.path.join(local, "orders.csv"))
    orig = readb(os.path.join(os.path.dirname(os.path.abspath(__file__)), "setup", "local", "orders.csv"))
    if data != orig:
        return False, "local orders.csv was changed"
    seen = (read(os.path.join(remote, ".totals-input")) or "").split()
    if hashlib.sha256(orig).hexdigest() not in seen:
        return False, "totals never read the whole of orders.csv on its stdin"
    got = read(os.path.join(local, "totals.txt"))
    want = fixture("totals")["summarize"](orig)
    if got is None:
        return False, "totals.txt missing"
    return got.strip() == want.strip(), f"totals.txt {got[:200]!r}, wanted {want!r}"
