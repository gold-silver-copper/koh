import hashlib, json, os, stat

HERE = os.path.dirname(os.path.abspath(__file__))


def check(local, remote):
    new = open(os.path.join(HERE, "setup", "local", "new-api.key"), "rb").read()
    old = open(os.path.join(HERE, "setup", "remote", "svc", "api.key"), "rb").read()
    for name, want in (("api.key", new), ("api.key.prev", old)):
        p = os.path.join(remote, "svc", name)
        if not os.path.exists(p):
            return False, f"no ~/svc/{name}"
        if open(p, "rb").read() != want:
            return False, f"~/svc/{name} does not hold the {'new' if want == new else 'old'} key"
        mode = stat.S_IMODE(os.stat(p).st_mode)
        if mode != 0o600:
            return False, f"~/svc/{name} has mode {mode:o}, wanted 600"
    rec = os.path.join(remote, ".bench", "reload.json")
    if not os.path.exists(rec):
        return False, "the service was never reloaded"
    last = json.loads(open(rec).read().splitlines()[-1])
    if last["sha256"] != hashlib.sha256(new).hexdigest():
        return False, "the last reload did not load the new key"
    return True, "key rotated and reloaded"
