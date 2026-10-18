import os

HERE = os.path.dirname(os.path.abspath(__file__))


def tree(root):
    out = {}
    for d, dirs, files in os.walk(root):
        for f in files:
            p = os.path.join(d, f)
            out[os.path.relpath(p, root)] = (open(p, "rb").read(), bool(os.stat(p).st_mode & 0o100))
    return out


def check(local, remote):
    dest = os.path.join(remote, "srv", "site")
    if not os.path.isdir(dest):
        return False, "no ~/srv/site on the remote"
    want, got = tree(os.path.join(HERE, "setup/local/site")), tree(dest)
    missing = sorted(set(want) - set(got))
    extra = sorted(set(got) - set(want))
    differ = sorted(p for p in set(want) & set(got) if want[p][0] != got[p][0])
    modes = sorted(p for p in set(want) & set(got) if want[p][1] != got[p][1])
    if missing or extra or differ or modes:
        return False, f"missing {missing}, left over {extra}, contents differ {differ}, executable bit wrong {modes}"
    return True, "~/srv/site is an exact copy, modes kept"
