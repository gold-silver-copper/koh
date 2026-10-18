import json
import os


def check(local, remote):
    path = os.path.join(remote, ".jobtop", "jobs.json")
    if not os.path.exists(path):
        return False, "jobtop was never started"
    jobs = json.load(open(path))
    killed = [j["name"] for j in jobs if j["killed"]]
    log = os.path.join(remote, ".jobtop", "actions.log")
    acts = open(log).read().split("\n") if os.path.exists(log) else []
    if killed != ["reindex-search"]:
        return False, f"killed jobs: {killed}, wanted only the stalled reindex-search"
    if not any(a.endswith(" reindex-search") for a in acts):
        return False, "the job was not killed through jobtop"
    return True, "the stalled job was killed, and only it"
