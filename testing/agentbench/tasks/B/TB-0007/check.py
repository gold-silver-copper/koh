import os


def check(local, remote):
    rec = os.path.join(remote, ".run-tests", "failed")
    if not os.path.exists(rec):
        return False, "run-tests was never run on the remote"
    want = open(rec).read().strip()
    path = os.path.join(local, "answer.txt")
    got = open(path).read().strip() if os.path.exists(path) else None
    return got == want, f"answer {got!r}, wanted {want!r}"
