import json
import os


def check(local, remote):
    d = os.path.join(remote, "sync")
    if not os.path.exists(os.path.join(d, "syncd.pid")):
        return False, "syncd was never started"
    pid = int(open(os.path.join(d, "syncd.pid")).read())
    try:
        st = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()[0]
        if st != "Z":
            return False, "syncd is still running"
    except OSError:
        pass
    sp = os.path.join(d, "state.json")
    if not os.path.exists(sp):
        return False, "syncd stopped without saving its state (killed outright?)"
    s = json.load(open(sp))
    if s.get("batches", 0) < 3:
        return False, f"syncd was stopped after only {s.get('batches')} batches"
    return True, f"syncd saved its state after {s['batches']} batches and exited"
