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
    res = (read(os.path.join(remote, ".watch-build.result")) or "").strip()
    trig = (read(os.path.join(remote, "trigger", "go")) or "").strip()
    if not trig:
        return False, "no build was triggered while watch-build was waiting"
    if res != f"seen {trig}":
        return False, f"watch-build did not finish on the trigger (result {res!r})"
    return True, "watch-build saw the trigger"
