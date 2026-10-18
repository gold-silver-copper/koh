import hashlib, json, os


def check(local, remote):
    spec = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "setup", "remote", "jobs", "retarget.spec")).read()
    want = f"retargeted-4200f-{hashlib.sha256(spec.encode()).hexdigest()[:8]}"
    q = os.path.join(remote, ".queue")
    done = []
    if os.path.isdir(q):
        for n in os.listdir(q):
            if n.endswith(".json"):
                s = json.load(open(os.path.join(q, n)))
                if s.get("state") == "done" and s.get("spec") == spec:
                    done.append(n)
    if not done:
        return False, "no retarget job finished in the queue"
    path = os.path.join(local, "answer.txt")
    got = open(path).read().strip() if os.path.exists(path) else None
    return got == want, f"answer {got!r}, wanted {want!r}"
