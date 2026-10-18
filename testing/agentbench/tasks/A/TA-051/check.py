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


def check(local, remote):
    done = read(os.path.join(remote, "reports", ".batch-7731.done"))
    if done is None:
        return False, "the worker never finished (or nightly was never run)"
    want = readb(os.path.join(remote, "reports", "batch-7731.txt"))
    got = readb(os.path.join(local, "report.txt"))
    if got is None:
        return False, "report.txt missing"
    if got != want:
        return False, f"report.txt ({len(got)} bytes) is not the finished batch-7731 report ({len(want)} bytes)"
    return True, "the finished batch report was copied"
