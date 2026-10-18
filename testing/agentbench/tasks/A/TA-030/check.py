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


OLD, NEW = 'server:\n  port: 8080\n  workers: 4\nlog:\n  level: info\n', 'server:\n  port: 8443\n  workers: 8\n  tls: true\nlog:\n  level: warn\n  format: json\n'
def check(local, remote):
    d = os.path.join(remote, "app", "config")
    cur, bak = read(os.path.join(d, "config.yaml")), read(os.path.join(d, "config.yaml.bak"))
    if bak != OLD:
        return False, f"config.yaml.bak is {bak!r}, wanted the old config"
    if cur != NEW:
        return False, f"config.yaml is {(cur or '')[:60]!r}, wanted the local config.yaml"
    return True, "config replaced, backup kept"
