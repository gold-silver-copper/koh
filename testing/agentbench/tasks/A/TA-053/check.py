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
    txt = read(os.path.join(remote, ".cache", "workers", "pids.json"))
    if txt is None:
        return False, "start-workers was never run"
    pids = json.loads(txt)
    if alive(pids["worker-4"]):
        return False, "the runaway worker-4 is still running"
    dead = [n for n, p in pids.items() if n != "worker-4" and not alive(p)]
    if dead:
        return False, f"healthy workers were stopped too: {dead}"
    return True, "only the runaway worker was stopped"
