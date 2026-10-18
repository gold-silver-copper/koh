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
    d = os.path.join(remote, ".cache", "farm")
    pids = (read(os.path.join(d, "pids")) or "").split()
    metrics = (read(os.path.join(d, "metrics.pid")) or "").strip()
    if not pids or not metrics:
        return False, "start-farm was never run"
    live = [p for p in pids if alive(p)]
    if live:
        return False, f"{len(live)} farm processes still running (pids {' '.join(live[:6])})"
    if not alive(metrics):
        return False, "metrics-agent was stopped too"
    return True, f"all {len(pids)} farm processes stopped, metrics-agent still running"
