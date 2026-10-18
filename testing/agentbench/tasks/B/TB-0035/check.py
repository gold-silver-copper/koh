import os


def check(local, remote):
    path = os.path.join(local, "answer.txt")
    got = open(path).read().strip() if os.path.exists(path) else None
    return got == "CVE-2025-31337", f"answer {got!r}, wanted 'CVE-2025-31337'"
