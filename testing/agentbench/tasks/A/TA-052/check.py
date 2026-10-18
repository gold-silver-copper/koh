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
    res = (read(os.path.join(remote, "run", "maint.result")) or "").split()
    patched = (read(os.path.join(remote, "run", "patched")) or "").strip()
    if not patched:
        return False, "the patch was never applied"
    if res[:2] != ["closed", "ok"]:
        return False, f"the maintenance window was not closed after the patch (result {' '.join(res)!r})"
    if res[2:] != [patched]:
        return False, "the window closed was not the one the patch was applied in"
    return True, "patched and the window closed"
