import os


def check(local, remote):
    path = os.path.join(local, "answer.txt")
    got = open(path).read().strip() if os.path.exists(path) else None
    want = "src/physics/broadphase.rs:812"
    return got == want, f"answer {got!r}, wanted {want!r}"
