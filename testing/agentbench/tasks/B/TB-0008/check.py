import os


def check(local, remote):
    path = os.path.join(local, "answer.txt")
    got = open(path).read().strip() if os.path.exists(path) else None
    return got == "ip-10-4-17-203", f"answer {got!r}, wanted 'ip-10-4-17-203'"
