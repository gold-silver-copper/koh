import json, os


def alive(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().rsplit(")", 1)[1].split()[0] not in ("Z", "X")
    except OSError:
        return False


def check(local, remote):
    rec = os.path.join(remote, ".bench", "threshold.json")
    if not os.path.exists(rec):
        return False, "stress-sim never reached its threshold"
    want = str(json.load(open(rec))["iteration"])
    pid = int(open(os.path.join(remote, ".bench", "stress.pid")).read())
    if alive(pid):
        return False, f"stress-sim (pid {pid}) is still running"
    path = os.path.join(local, "answer.txt")
    got = open(path).read().strip() if os.path.exists(path) else None
    return got == want, f"answer {got!r}, wanted {want!r}"
