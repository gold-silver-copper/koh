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


import hashlib
ORIG = '# app.conf: settings for the order service\n\nopt_03 = fast\nopt_04 = fast\nopt_05 = 326\nopt_06 = off\n# section 1\nopt_08 = fast\n\nopt_10 = strict\nopt_11 = strict\nopt_12 = off\nopt_13 = on\n# section 2\nopt_15 = 8\nopt_16 = strict\nopt_17 = on\n\nopt_19 = off\nopt_20 = off\n# section 3\nopt_22 = on\nopt_23 = fast\nopt_24 = fast\nopt_25 = 18\nopt_26 = fast\n\n# section 4\nopt_29 = on\nopt_30 = 333\nopt_31 = off\nopt_32 = on\nopt_33 = on\nopt_34 = off\n# section 5\n\nmax_connections = 10000\nopt_38 = 283\nopt_39 = fast\nopt_40 = off\nopt_41 = on\n# section 6\nopt_43 = off\nopt_44 = off\n\nopt_46 = strict\nopt_47 = on\nopt_48 = strict\n# section 7\nopt_50 = strict\nopt_51 = fast\nlog_dir = ~/app/logs\nopt_53 = 103\n\nopt_55 = off\n# section 8\nopt_57 = strict\nopt_58 = 210\nopt_59 = fast\nopt_60 = fast\n'
def check(local, remote):
    path = os.path.join(remote, "app", "app.conf")
    now = read(path)
    if now is None:
        return False, "app.conf missing"
    started = read(os.path.join(remote, "app", "started.txt"))
    if started is None:
        return False, "the app never started (no ~/app/started.txt)"
    if started.strip() != "ok " + hashlib.sha256(now.encode()).hexdigest()[:16]:
        return False, "started.txt is not from a start with the current app.conf"
    old = [l for l in ORIG.splitlines() if not l.startswith(("max_connections", "log_dir"))]
    new = [l for l in now.splitlines() if not l.startswith(("max_connections", "log_dir"))]
    if [l.strip() for l in old if l.strip()] != [l.strip() for l in new if l.strip()]:
        return False, "settings other than max_connections and log_dir were changed"
    return True, "the app starts and the other settings are untouched"
