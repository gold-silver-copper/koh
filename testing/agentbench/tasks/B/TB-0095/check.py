import json, os


def check(local, remote):
    rec = os.path.join(remote, ".bench", "deploys.json")
    if not os.path.exists(rec):
        return False, "nothing was deployed"
    deploys = [json.loads(l) for l in open(rec) if l.strip()]
    want = {"build": "nightly-2026-10-14 (arm64)", "env": "staging"}
    if deploys != [want]:
        return False, f"deploys {deploys}, wanted only {want}"
    return True, "deployed the right build to staging"
