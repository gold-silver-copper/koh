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
    st = read(os.path.join(remote, "work", "app", "config.status"))
    if st is None:
        return False, "~/work/app/config.status missing: configure never succeeded"
    want = os.path.realpath(os.path.join(remote, "opt", "app"))
    for line in st.splitlines():
        if line.startswith("prefix="):
            got = line[len("prefix="):].rstrip("/")
            ok = os.path.realpath(got) == want
            return ok, f"prefix {got!r}, wanted {want!r}"
    return False, "config.status has no prefix line"
