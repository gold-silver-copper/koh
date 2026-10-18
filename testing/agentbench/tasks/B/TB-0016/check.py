import json
import os


def check(local, remote):
    d = os.path.join(remote, "reindex")
    if not os.path.exists(os.path.join(d, "finished.json")):
        return False, "the reindex never finished"
    if not os.path.exists(os.path.join(d, "verified")):
        return False, "reindex --verify was never run successfully"
    want = str(json.load(open(os.path.join(d, "finished.json")))["documents"])
    path = os.path.join(local, "answer.txt")
    got = open(path).read().strip() if os.path.exists(path) else None
    return got == want, f"answer {got!r}, wanted {want!r}"
