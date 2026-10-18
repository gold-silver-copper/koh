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


WANT = 'Q3 summary, final, version 2\n\nrevenue: 4.81M (+6.2%)\nchurn: 2.1%\nheadcount: 212\n'
def check(local, remote):
    got = read(os.path.join(local, "q3.txt"))
    if got is None:
        return False, "q3.txt missing"
    return got == WANT, "q3.txt is the v2 final report" if got == WANT else f"q3.txt has {got[:60]!r}"
