import hashlib, json, os


def check(local, remote):
    p = os.path.join(remote, "model", "final.json")
    if not os.path.exists(p):
        return False, "no ~/model/final.json: training never completed"
    w = hashlib.sha256(b"init").hexdigest()
    for e in range(1, 13):
        w = hashlib.sha256(f"{w}:{e}".encode()).hexdigest()
    got = json.load(open(p))
    if got != {"epochs": 12, "weights": w}:
        return False, f"~/model/final.json is not from a complete training run: {got}"
    return True, "training completed all 12 epochs"
