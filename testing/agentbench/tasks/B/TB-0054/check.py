import os


def alive(pid):
    try:
        st = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()[0]
        return st != "Z" and b"worker" in open(f"/proc/{pid}/cmdline", "rb").read()
    except OSError:
        return False


def check(local, remote):
    path = os.path.join(remote, ".workers", "pids")
    if not os.path.exists(path):
        return False, "start-workers was never run"
    pids = {int(n): int(p) for n, p in (l.split() for l in open(path) if l.strip())}
    if alive(pids[3]):
        return False, "the leaking worker (worker 3) is still running"
    dead = [n for n in (1, 2, 4) if not alive(pids[n])]
    if dead:
        return False, f"healthy workers were stopped too: {dead}"
    return True, "the leaking worker was stopped and the others still run"
