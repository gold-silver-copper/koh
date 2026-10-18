import os


def check(local, remote):
    if not os.path.exists(os.path.join(remote, ".cache", "check-deps", "ran")):
        return False, "check-deps was never run on the remote"
    path = os.path.join(local, "answer.txt")
    got = open(path).read().strip() if os.path.exists(path) else None
    return got == "5", f"answer {got!r}, wanted '5'"
