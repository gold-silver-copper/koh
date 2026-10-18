import json, os


def check(local, remote):
    recs = {}
    for name in ("lighting", "shaders"):
        p = os.path.join(remote, ".bench", f"{name}.json")
        if not os.path.exists(p):
            return False, f"{name} job never finished"
        recs[name] = json.load(open(p))
    a, b = recs["lighting"], recs["shaders"]
    if not (a["start"] < b["end"] and b["start"] < a["end"]):
        return False, "the two jobs did not run at the same time"
    want = [f"lighting: {a['checksum']}", f"shaders: {b['compiled']}"]
    path = os.path.join(local, "answer.txt")
    got = [l.strip() for l in open(path).read().splitlines() if l.strip()] if os.path.exists(path) else None
    return got == want, f"answer {got!r}, wanted {want!r}"
