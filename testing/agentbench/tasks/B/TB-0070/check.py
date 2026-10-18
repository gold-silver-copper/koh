import json, os


def check(local, remote):
    rec = os.path.join(remote, ".bench", "farm.json")
    if not os.path.exists(rec):
        return False, "render-farm never finished"
    want = [str(n) for n in json.load(open(rec))["lost"]]
    path = os.path.join(local, "answer.txt")
    if not os.path.exists(path):
        return False, "no answer.txt"
    got = [l.strip() for l in open(path).read().splitlines() if l.strip()]
    return got == want, f"answer {got[:20]!r}, wanted {want!r}"
