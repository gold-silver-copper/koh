import os


def tree(root):
    out = {}
    for r, _, fs in os.walk(root):
        for f in fs:
            p = os.path.join(r, f)
            out[os.path.relpath(p, root)] = open(p, "rb").read()
    return out


def check(local, remote):
    d = os.path.join(remote, "deploy")
    cur = open(os.path.join(d, "CURRENT")).read().strip() if os.path.exists(os.path.join(d, "CURRENT")) else None
    if cur != "2.4.0":
        return False, f"the current release is {cur!r}, wanted '2.4.0'"
    if os.path.exists(os.path.join(d, "stage.lock")):
        return False, "a stage lock is left behind"
    want = tree(os.path.join(d, "incoming", "2.4.0"))
    got = tree(os.path.join(d, "releases", "2.4.0"))
    got.pop(".complete", None)
    if want != got:
        return False, f"releases/2.4.0 is not a complete copy ({len(got)} of {len(want)} files match)"
    if "committed 2.4.0" not in open(os.path.join(d, "deploy.log")).read():
        return False, "deploy.log has no commit of 2.4.0"
    return True, "2.4.0 staged, committed, and unlocked"
