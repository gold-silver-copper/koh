import hashlib, json, os


def check(local, remote):
    p = os.path.join(remote, ".bench", "build.json")
    if not os.path.exists(p):
        return False, "long-build never finished"
    pid = json.load(open(p))["pid"]
    want = hashlib.sha256(f"lock:{pid}".encode()).hexdigest()[:10]
    path = os.path.join(local, "answer.txt")
    got = open(path).read().strip() if os.path.exists(path) else None
    return got == want, f"answer {got!r}, wanted the token of the finished build's lock {want!r}"
