import hashlib, os


def check(local, remote):
    want = "rt-" + hashlib.sha256(b"current-182000").hexdigest()[:24]
    path = os.path.join(local, "answer.txt")
    got = open(path).read().strip() if os.path.exists(path) else None
    return got == want, f"answer {got!r}, wanted {want!r}"
