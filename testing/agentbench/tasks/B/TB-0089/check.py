import hashlib, os


def tree(root):
    out = {}
    for d, _, files in os.walk(root):
        for f in files:
            p = os.path.join(d, f)
            out[os.path.relpath(p, root)] = hashlib.sha256(open(p, "rb").read()).hexdigest()
    return out


def check(local, remote):
    want = tree(os.path.join(os.path.dirname(os.path.abspath(__file__)), "setup", "remote", "reports"))
    root = os.path.join(local, "reports")
    if not os.path.isdir(root):
        return False, "no reports/ directory locally"
    got = tree(root)
    missing = sorted(set(want) - set(got))
    extra = sorted(set(got) - set(want))
    wrong = sorted(k for k in set(want) & set(got) if want[k] != got[k])
    if missing or extra or wrong:
        return False, f"missing {missing[:5]}, extra {extra[:5]}, different content {wrong[:5]}"
    return True, f"all {len(want)} files match"
