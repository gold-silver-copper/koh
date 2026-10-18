import os


def check(local, remote):
    s = os.path.join(remote, "backup", "summary.txt")
    if not os.path.exists(s):
        return False, "the backup never completed"
    want = open(s).read().strip()
    path = os.path.join(local, "summary.txt")
    got = open(path).read().strip() if os.path.exists(path) else None
    return got == want, f"local summary {got!r}, wanted {want!r}"
