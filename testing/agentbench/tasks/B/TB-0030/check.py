import os

HERE = os.path.dirname(os.path.abspath(__file__))


def tree(root):
    out = {}
    for d, dirs, files in os.walk(root):
        for f in files:
            p = os.path.join(d, f)
            out[os.path.relpath(p, root)] = open(p, "rb").read()
    return out


def check(local, remote):
    dest = os.path.join(local, "inbox")
    if not os.path.isdir(dest):
        return False, "no inbox/ in the local directory"
    want, got = tree(os.path.join(HERE, "setup/remote/inbox")), tree(dest)
    missing, extra = sorted(set(want) - set(got)), sorted(set(got) - set(want))
    differ = sorted(p for p in set(want) & set(got) if want[p] != got[p])
    if missing or extra or differ:
        return False, f"missing {missing}, unexpected {extra}, contents differ {differ}"
    return True, f"all {len(want)} files copied with their names"
