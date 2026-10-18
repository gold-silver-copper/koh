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
    path = os.path.join(local, "db.snapshot")
    if not os.path.exists(path):
        return False, "db.snapshot missing"
    h = hashlib.sha256()
    for c in fixture("snapshot")["chunks"]():
        h.update(c)
    g = hashlib.sha256()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            g.update(c)
    size = os.path.getsize(path)
    return g.digest() == h.digest(), "db.snapshot identical" if g.digest() == h.digest() else f"db.snapshot differs ({size} bytes)"
