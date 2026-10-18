import os


def alive(pid):
    try:
        st = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()[0]
        return st != "Z" and b"farm" in open(f"/proc/{pid}/cmdline", "rb").read()
    except OSError:
        return False


def check(local, remote):
    rec = os.path.join(remote, ".farm-spawned")
    if not os.path.exists(rec):
        return False, "the farm was never started"
    procs = [l.split() for l in open(rec) if l.strip()]
    left = [f"{kind} {pid}" for kind, pid in procs if alive(int(pid))]
    if left:
        return False, f"still running: {left}"
    return True, f"the farm and all {len(procs) - 1} worker processes are stopped"
