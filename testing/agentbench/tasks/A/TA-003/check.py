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


WANT = ['warning: table audit_log has no primary key', 'warning: column users.legacy_id is deprecated', 'error: migration 0042_split_accounts failed: duplicate key value (account_id)=(1187)']
def check(local, remote):
    err = read(os.path.join(local, "errors.txt"))
    st = read(os.path.join(local, "status.txt"))
    if err is None or st is None:
        return False, "errors.txt or status.txt missing"
    lines = err.rstrip("\n").split("\n")
    if lines != WANT:
        return False, f"errors.txt has {lines[:6]!r}, wanted exactly the 3 stderr lines {WANT!r}"
    if st.strip() != "2":
        return False, f"status {st.strip()!r}, wanted '2'"
    return True, "stderr and status right"
