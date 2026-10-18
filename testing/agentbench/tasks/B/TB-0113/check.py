import json, os


def check(local, remote):
    p = os.path.join(remote, ".bench", "pair.json")
    sides = {json.loads(l)["side"] for l in open(p)} if os.path.exists(p) else set()
    if sides != {"host", "device"}:
        return False, f"pairing succeeded on {sorted(sides) or 'neither side'}, wanted both"
    return True, "both sides report pairing succeeded"
