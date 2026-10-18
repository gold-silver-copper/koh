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
    smoke = (read(os.path.join(remote, "run", "smoke.result")) or "").split()
    if "pass" not in smoke:
        return False, f"the smoke test never passed ({smoke})"
    how = (read(os.path.join(remote, "run", "dev.shutdown")) or "").strip()
    if how != "SIGINT":
        pid = (read(os.path.join(remote, "run", "dev.pid")) or "").strip()
        state = "still running" if pid and alive(pid) else "not shut down cleanly"
        return False, f"serve-dev was {state} (shutdown record {how!r}, wanted an interrupt)"
    return True, "smoke test passed and the server shut down on Ctrl-C"
