import os


def check(local, remote):
    if not os.path.exists(os.path.join(remote, ".bench", "manual.ran")):
        return False, "the manual was never opened"
    path = os.path.join(local, "answer.txt")
    got = open(path).read().strip() if os.path.exists(path) else None
    return got == "384 MiB", f"answer {got!r}, wanted '384 MiB'"
