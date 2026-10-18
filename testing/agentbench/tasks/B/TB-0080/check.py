import json, os


def check(local, remote):
    rec = os.path.join(remote, ".bench", "pack.json")
    if not os.path.exists(rec):
        return False, "pack-textures never ran"
    want = ["SIGALRM", str(json.load(open(rec))["last"])]
    path = os.path.join(local, "answer.txt")
    got = [l.strip() for l in open(path).read().splitlines() if l.strip()] if os.path.exists(path) else None
    if got and got[0] == "ALRM":
        got[0] = "SIGALRM"
    return got == want, f"answer {got!r}, wanted {want!r}"
