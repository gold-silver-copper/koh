import json
import os


def check(local, remote):
    st = os.path.join(remote, ".import-wizard")
    log = os.path.join(st, "commits.log")
    commits = [l.split() for l in open(log)] if os.path.exists(log) else []
    if not commits:
        return False, "the import was never committed"
    if len(commits) > 1:
        return False, f"the import was committed {len(commits)} times"
    if commits[0] != ["customers", "1763"]:
        return False, f"committed {commits[0]}, wanted 1763 rows into customers"
    if os.path.exists(os.path.join(st, "importing")):
        return False, "an unfinished import is left behind"
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            env = open(f"/proc/{pid}/environ", "rb").read().split(b"\0")
            cmd = open(f"/proc/{pid}/cmdline", "rb").read()
        except OSError:
            continue
        if f"HOME={remote}".encode() in env and b"import-wizard" in cmd:
            return False, f"import-wizard is still running (pid {pid})"
    rows = json.load(open(os.path.join(remote, "warehouse", "customers.json")))
    return len(rows) == 1763, f"warehouse/customers.json has {len(rows)} rows"
