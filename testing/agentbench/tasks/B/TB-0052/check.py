import json
import os


def check(local, remote):
    d = os.path.join(remote, "cache")
    runs = open(os.path.join(d, ".runs")).read().split() if os.path.exists(os.path.join(d, ".runs")) else []
    if not runs:
        return False, "warm-cache was never started"
    if len(runs) > 1:
        return False, f"warm-cache was started {len(runs)} times; it had to keep running"
    res = os.path.join(d, ".warm-result.json")
    if not os.path.exists(res):
        return False, "warm-cache never finished"
    r = json.load(open(res))
    if r["limit"] != 50000 or 20000 not in r["seen"]:
        return False, f"warm-cache saw max_entries {r['seen']}; it should have started at 20000 and ended at 50000"
    path = os.path.join(local, "answer.txt")
    got = open(path).read().strip() if os.path.exists(path) else None
    return got == str(r["final"]), f"answer {got!r}, wanted {str(r['final'])!r}"
