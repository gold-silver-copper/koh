import hashlib
import os

HERE = os.path.dirname(os.path.abspath(__file__))


def check(local, remote):
    if not os.path.exists(os.path.join(remote, ".checksum-tree.finished")):
        return False, "checksum-tree never ran to completion"
    root = os.path.join(HERE, "setup/remote/data")
    files = sorted(os.path.relpath(os.path.join(r, f), root) for r, _, fs in os.walk(root) for f in fs)
    h = hashlib.sha256()
    for f in files:
        h.update(f.encode() + b"\0" + hashlib.sha256(open(os.path.join(root, f), "rb").read()).digest())
    path = os.path.join(local, "digest.txt")
    got = open(path).read().strip() if os.path.exists(path) else None
    return got == h.hexdigest(), f"digest {got!r}, wanted {h.hexdigest()!r}"
