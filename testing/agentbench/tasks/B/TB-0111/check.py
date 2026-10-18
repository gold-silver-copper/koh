import hashlib, json, os


def alive(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().rsplit(")", 1)[1].split()[0] not in ("Z", "X")
    except OSError:
        return False


def check(local, remote):
    p = os.path.join(remote, ".bench", "api-dev.json")
    if not os.path.exists(p):
        return False, "api-dev never ran"
    rec = json.load(open(p))
    port = rec["port"]
    want = "tok-" + hashlib.sha256(f"api-dev-{port}".encode()).hexdigest()[:14]
    path = os.path.join(local, "answer.txt")
    got = open(path).read().strip() if os.path.exists(path) else None
    if got != want:
        return False, f"answer {got!r}, wanted {want!r}"
    if alive(rec["pid"]):
        return False, "api-dev is still running"
    if not rec["clean"]:
        return False, "api-dev was not quit with q"
    return True, "token fetched and api-dev quit cleanly"
