import json, os


def check(local, remote):
    p = os.path.join(remote, ".bench", "migrate.json")
    recs = [json.loads(l) for l in open(p)] if os.path.exists(p) else []
    done = [r for r in recs if r.get("result") == "done"]
    if not done:
        return False, f"the migration never completed (records: {recs})"
    if done[-1]["answer"] != "y":
        return False, f"the question was answered {done[-1]['answer']!r}, not 'y'"
    return True, "migration completed with the orphaned rows deleted"
