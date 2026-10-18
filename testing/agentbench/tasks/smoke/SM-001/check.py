import os


def check(local, remote):
    path = os.path.join(local, "answer.txt")
    got = open(path).read().strip() if os.path.exists(path) else None
    return got == "3", f"answer {got!r}, wanted '3'"
