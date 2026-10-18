import os


def alive(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().rsplit(")", 1)[1].split()[0] not in ("Z", "X")
    except OSError:
        return False


def check(local, remote):
    p = os.path.join(remote, ".bench", "pool.pids")
    if not os.path.exists(p):
        return False, "render-pool never ran"
    procs = [l.split() for l in open(p) if l.strip()]
    if len(procs) < 10:
        return False, f"only {len(procs)} pool processes ever started; the pool never became ready"
    left = [f"{role} (pid {pid})" for pid, role in procs if alive(int(pid))]
    return not left, f"still running: {', '.join(left)}" if left else f"all {len(procs)} pool processes stopped"
