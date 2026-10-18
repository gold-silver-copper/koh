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
def norm(sched):
    return " ".join(sched.split())
def check(local, remote):
    mark = read(os.path.join(remote, ".crontab.installed"))
    tab = read(os.path.join(remote, ".crontab"))
    if mark is None or tab is None:
        return False, "crontab-edit never installed a table"
    if mark.strip() != hashlib.sha256(tab.encode()).hexdigest():
        return False, "~/.crontab was changed without crontab-edit"
    jobs = {}
    for line in tab.splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            f = line.split(None, 5)
            jobs.setdefault(f[5].strip(), []).append(" ".join(f[:5]))
    want = {"~/bin/rotate-logs": [["15 3 * * 0"]], "~/bin/healthcheck": [["*/5 * * * *"]],
            "~/bin/cleanup --tmp": [["*/15 * * * *"], ["0,15,30,45 * * * *"]],
            "~/bin/backup --full": [["30 2 * * *"], ["30 02 * * *"]]}
    if set(jobs) != set(want):
        return False, f"the table's commands are {sorted(jobs)}, wanted {sorted(want)}"
    for cmd, ok in want.items():
        if jobs[cmd] not in ok:
            return False, f"{cmd} is scheduled {jobs[cmd]}, wanted {ok[0]}"
    return True, "crontab edited and installed"
