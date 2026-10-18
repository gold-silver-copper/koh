import os

WANT = ["2", "warning: report: slow step 11 (7s)"]


def check(local, remote):
    if not os.path.exists(os.path.join(remote, ".nightly", "ran")):
        return False, "nightly was never run to the end on the remote"
    path = os.path.join(local, "answer.txt")
    if not os.path.exists(path):
        return False, "no answer.txt"
    got = [l.rstrip("\r") for l in open(path).read().strip("\n").split("\n")]
    return got == WANT, f"answer {got!r}, wanted {WANT!r}"
