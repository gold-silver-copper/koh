import os


def alive(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().rsplit(")", 1)[1].split()[0] not in ("Z", "X")
    except OSError:
        return False


def check(local, remote):
    pids = {}
    for s in range(4):
        p = os.path.join(remote, ".bench", f"worker-{s}.pid")
        if not os.path.exists(p):
            return False, "the workers were never started"
        pids[s] = int(open(p).read())
    if alive(pids[2]):
        return False, "the runaway worker (shard 2) still runs"
    dead = [s for s in (0, 1, 3) if not alive(pids[s])]
    return not dead, f"workers {dead} were stopped too" if dead else "only the runaway was stopped"
