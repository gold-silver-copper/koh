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


import subprocess, sys
def check(local, remote):
    got = read(os.path.join(local, "failed.txt"))
    if got is None:
        return False, "failed.txt missing"
    names = fixture("run-tests")["plan"]()
    want = [n for n, ok in names if not ok]
    lines = [l.strip() for l in got.splitlines() if l.strip()]
    return lines == want, f"failed.txt has {lines!r}, wanted {want!r}"
