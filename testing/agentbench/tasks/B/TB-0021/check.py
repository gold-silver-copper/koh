import os


def check(local, remote):
    log = os.path.join(remote, "logs", "queue-worker.log")
    if not os.path.exists(log):
        return False, "queue-worker was never run"
    want = [l for l in open(log).read().splitlines() if " FATAL " in l]
    if not want:
        return False, "queue-worker never got as far as its fatal error"
    path = os.path.join(local, "fatal.txt")
    got = open(path).read().strip("\r\n") if os.path.exists(path) else None
    return got == want[0], f"fatal.txt has {got!r}, wanted {want[0]!r}"
