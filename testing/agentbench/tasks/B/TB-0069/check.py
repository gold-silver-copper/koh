import json, os


def check(local, remote):
    rec = os.path.join(remote, ".bench", "train.json")
    if not os.path.exists(rec):
        return False, "train-epochs never finished"
    rec = json.load(open(rec))
    want = [str(rec["nans"]), rec["val"]]
    path = os.path.join(local, "answer.txt")
    got = [l.strip() for l in open(path).read().splitlines() if l.strip()] if os.path.exists(path) else None
    return got == want, f"answer {got!r}, wanted {want!r}"
