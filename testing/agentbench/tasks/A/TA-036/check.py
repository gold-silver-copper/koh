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
    txt = read(os.path.join(remote, "netconfig.json"))
    if txt is None:
        return False, "netconfig never saved (~/netconfig.json missing)"
    got = json.loads(txt)
    want = {"hostname": "build-07", "address": "10.20.30.47/24", "gateway": "10.20.30.1",
            "dns": "10.20.0.53 10.20.0.54"}
    return got == want, f"saved {got}, wanted {want}"
