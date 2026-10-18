import hashlib, os, stat


def tree(root):
    out = {}
    for d, _, files in os.walk(root):
        for f in files:
            p = os.path.join(d, f)
            out[os.path.relpath(p, root)] = (hashlib.sha256(open(p, "rb").read()).hexdigest(),
                                              bool(os.stat(p).st_mode & stat.S_IXUSR))
    return out


def check(local, remote):
    want = tree(os.path.join(os.path.dirname(os.path.abspath(__file__)), "setup", "local", "deploy"))
    root = os.path.join(remote, "srv", "deploy")
    if not os.path.isdir(root):
        return False, "no ~/srv/deploy on the remote"
    got = tree(root)
    bad = []
    for k, (h, x) in want.items():
        if k not in got:
            bad.append(f"{k} missing")
        elif got[k][0] != h:
            bad.append(f"{k} differs")
        elif got[k][1] != x:
            bad.append(f"{k} {'should' if x else 'should not'} be executable")
    bad += [f"{k} extra" for k in got if k not in want]
    return not bad, "; ".join(bad) or f"all {len(want)} files match, modes too"
