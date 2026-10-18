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
    if read(os.path.join(remote, "db", "status-checked")) is None:
        return False, "db-status never found the server up"
    pid = (read(os.path.join(remote, "db", "db.pid")) or "").strip()
    if pid and alive(pid):
        return False, f"the database server (pid {pid}) is still running"
    log = read(os.path.join(remote, "db", "shutdown.log")) or ""
    return "clean shutdown" in log, "clean shutdown recorded" if "clean shutdown" in log else "no clean shutdown recorded"
