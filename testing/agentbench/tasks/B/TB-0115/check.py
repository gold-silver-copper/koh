import json, os, random


def alive(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().rsplit(")", 1)[1].split()[0] not in ("Z", "X")
    except OSError:
        return False


def check(local, remote):
    pf = os.path.join(remote, ".bench", "kvd.pid")
    if not os.path.exists(pf):
        return False, "kvd never started"
    if alive(int(open(pf).read())):
        return False, "kvd is still running"
    db = os.path.join(remote, "kv", "data.db")
    if not os.path.exists(db):
        return False, "kvd did not save ~/kv/data.db (it was not shut down cleanly)"
    rng = random.Random(115)
    want = {f"player:{i:04d}": str(rng.randint(0, 10**6)) for i in range(500)}
    got = json.load(open(db))
    return got == want, f"~/kv/data.db holds {len(got)} keys" + ("" if got == want else ", not the loaded data")
