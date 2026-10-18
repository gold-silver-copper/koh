import hashlib
import os


def check(local, remote):
    idx = os.path.join(remote, "index", "index.json")
    if not os.path.exists(idx):
        return False, "fetch-index never succeeded (no ~/index/index.json)"
    want = hashlib.sha256(open(idx, "rb").read()).hexdigest()
    path = os.path.join(local, "answer.txt")
    got = open(path).read().strip() if os.path.exists(path) else None
    return got == want, f"answer {got!r}, wanted {want!r}"
