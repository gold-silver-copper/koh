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
    path = os.path.join(local, "full.bin")
    if not os.path.exists(path):
        return False, "full.bin missing"
    h = hashlib.sha256()
    for c in fixture("export-data")["chunks"]():
        h.update(c)
    g = hashlib.sha256()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            g.update(c)
    ok = g.digest() == h.digest()
    return ok, "full.bin is the complete export" if ok else f"full.bin differs ({os.path.getsize(path)} bytes)"
