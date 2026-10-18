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
    log = (read(os.path.join(remote, "crawl", "processed.log")) or "").split()
    if not log:
        return False, "crawl never processed anything"
    want = [f"item-{i:03d}" for i in range(1, 201)]
    dupes = sorted({x for x in log if log.count(x) > 1})
    if dupes:
        return False, f"items processed twice: {dupes[:5]}"
    if sorted(log) != want:
        return False, f"{len(set(want) - set(log))} items never processed"
    return True, "all 200 items processed once"
