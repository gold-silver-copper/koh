import os


def check(local, remote):
    path = os.path.join(local, "answer.txt")
    got = open(path).read().strip("\n") if os.path.exists(path) else None
    return got == "/mnt/backup volume 2", f"answer {got!r}, wanted '/mnt/backup volume 2'"
