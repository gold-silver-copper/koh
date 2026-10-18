import json, os


def alive(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().rsplit(")", 1)[1].split()[0] not in ("Z", "X")
    except OSError:
        return False


def check(local, remote):
    st = os.path.join(remote, ".jobs", "state.json")
    if not os.path.exists(st):
        return False, "jobtop never started the jobs"
    jobs = json.load(open(st))
    if len(jobs) != 8:
        return False, f"jobtop's state lists {len(jobs)} jobs, not 8"
    rec = os.path.join(remote, ".bench", "jobtop.json")
    stopped = [json.loads(l)["stopped"] for l in open(rec)] if os.path.exists(rec) else []
    if stopped != ["bake-ao-tile-17"]:
        return False, f"jobtop stopped {stopped}, wanted only bake-ao-tile-17"
    if alive(jobs["bake-ao-tile-17"]):
        return False, "bake-ao-tile-17 still runs"
    dead = [n for n, p in jobs.items() if n != "bake-ao-tile-17" and not alive(p)]
    return not dead, f"other jobs stopped: {dead}" if dead else "only bake-ao-tile-17 stopped"
