import os


def check(local, remote):
    rec = os.path.join(remote, ".canary", "verdict")
    if not os.path.exists(rec):
        return False, "deploy-canary never finished"
    want = open(rec).read().strip()
    path = os.path.join(local, "verdict.txt")
    got = open(path).read().strip() if os.path.exists(path) else None
    return got == want, f"verdict {got!r}, wanted {want!r}"
