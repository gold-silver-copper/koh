import json
import os


def check(local, remote):
    d = os.path.join(remote, "migrate")
    ck = os.path.join(d, "checkpoint.json")
    if not os.path.exists(ck):
        return False, "the migration was never started"
    if not json.load(open(ck)).get("finished"):
        return False, f"the migration did not finish: {open(ck).read().strip()}"
    done = [l.split()[1] for l in open(os.path.join(d, "events.log")) if l.startswith("done ")]
    twice = sorted({s for s in done if done.count(s) > 1})
    if twice:
        return False, f"shards migrated more than once: {twice}"
    if sorted(done) != [str(i) for i in range(1, 9)]:
        return False, f"completed shards {done}"
    return True, "all 8 shards migrated exactly once"
