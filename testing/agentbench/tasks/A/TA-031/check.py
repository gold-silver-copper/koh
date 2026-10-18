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


WANT = ['2026-10-02/worker-6.log', '2026-10-03/worker-3.log', '2026-10-03/worker-4.log', '2026-10-04/worker-2.log', '2026-10-04/worker-8.log', '2026-10-06/worker-4.log', '2026-10-06/worker-5.log', '2026-10-06/worker-7.log', '2026-10-07/worker-1.log', '2026-10-10/worker-5.log']
def check(local, remote):
    root = os.path.join(local, "oom")
    have = sorted(os.path.relpath(os.path.join(d, f), root) for d, _, fs in os.walk(root) for f in fs)
    if have != WANT:
        return False, f"oom/ has {have}, wanted {WANT}"
    for rel in WANT:
        if readb(os.path.join(root, rel)) != readb(os.path.join(remote, "logs", rel)):
            return False, f"oom/{rel} differs from the remote log"
    return True, f"{len(WANT)} OOM logs copied"
