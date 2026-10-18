import json, os


def check(local, remote):
    p = os.path.join(remote, ".keystore", "unlocked.json")
    if not os.path.exists(p):
        return False, "the keystore was never unlocked"
    got = json.load(open(p))
    want = {"minutes": 45, "signing": False}
    return got == want, f"unlocked with {got}, wanted {want}"
