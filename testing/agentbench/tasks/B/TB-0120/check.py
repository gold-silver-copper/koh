import json, os


def check(local, remote):
    want = ["seed,median_ms"]
    for s in range(1, 6):
        p = os.path.join(remote, ".bench", f"bench-{s}.json")
        if not os.path.exists(p):
            return False, f"bench-run was never run for seed {s}"
        want.append(f"{s},{json.load(open(p))['median']}")
    path = os.path.join(local, "results.csv")
    if not os.path.exists(path):
        return False, "no results.csv"
    got = [l.strip() for l in open(path).read().splitlines() if l.strip()]
    return got == want, f"results.csv {got}, wanted {want}"
