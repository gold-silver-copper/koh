import json
import os


def alive(pid, name):
    try:
        st = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()[0]
        return st != "Z" and name.encode() in open(f"/proc/{pid}/cmdline", "rb").read()
    except OSError:
        return False


def check(local, remote):
    path = os.path.join(remote, ".devserver", "smoke.json")
    if not os.path.exists(path):
        return False, "smoke never reported success"
    pid = json.load(open(path))["pid"]
    if not alive(pid, "devserver"):
        return False, "smoke passed, but the dev server is no longer running"
    return True, "smoke passed and the dev server is still running"
