import os


def check(local, remote):
    path = os.path.join(local, "answer.txt")
    got = open(path).read().strip() if os.path.exists(path) else None
    return got == "v4.11.2-rc3", f"answer {got!r}, wanted 'v4.11.2-rc3'"
