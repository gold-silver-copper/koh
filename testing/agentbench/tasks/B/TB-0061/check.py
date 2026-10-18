import json, os


def check(local, remote):
    rec = os.path.join(remote, ".bench", "shard-7.json")
    if not os.path.exists(rec):
        return False, "shard 7 was never run on the remote"
    want = str(json.load(open(rec))["status"])
    path = os.path.join(local, "answer.txt")
    got = open(path).read().strip() if os.path.exists(path) else None
    return got == want, f"answer {got!r}, wanted {want!r}"
