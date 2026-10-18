import json, os


def check(local, remote):
    rec = os.path.join(remote, ".bench", "done.json")
    if not os.path.exists(rec):
        return False, "export-assets never finished"
    want = str(json.load(open(rec))["total"])
    path = os.path.join(local, "answer.txt")
    got = open(path).read().strip() if os.path.exists(path) else None
    return got == want, f"answer {got!r}, wanted {want!r}"
