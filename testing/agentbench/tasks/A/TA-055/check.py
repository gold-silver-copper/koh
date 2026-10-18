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
    first = (read(os.path.join(remote, ".cache", "proxy-first-pid")) or "").strip()
    if not first:
        return False, "the proxy was never started"
    if not alive(first):
        return False, f"the first proxy process ({first}) is not running any more"
    log = read(os.path.join(remote, "proxy", "proxy.log")) or ""
    if f"[{first}] reloaded: upstream=10.0.0.9:8080" not in log:
        return False, "the running proxy never reloaded upstream 10.0.0.9:8080"
    return True, "the proxy reloaded in place"
