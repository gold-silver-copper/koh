import os

HERE = os.path.dirname(os.path.abspath(__file__))


def tree(root, skip=None):
    out = {}
    for d, dirs, files in os.walk(root):
        rel = os.path.relpath(d, root)
        if skip and (rel == skip or rel.startswith(skip + os.sep)):
            continue
        for f in files:
            p = os.path.join(d, f)
            out[os.path.relpath(p, root)] = (open(p, "rb").read(), bool(os.stat(p).st_mode & 0o100))
    return out


def check(local, remote):
    dest = os.path.join(remote, "www")
    if not os.path.isdir(dest):
        return False, "~/www is gone from the remote"
    up_want = tree(os.path.join(HERE, "setup/remote/www/uploads"))
    up_got = tree(os.path.join(dest, "uploads")) if os.path.isdir(os.path.join(dest, "uploads")) else {}
    if {k: v[0] for k, v in up_want.items()} != {k: v[0] for k, v in up_got.items()}:
        return False, f"~/www/uploads was changed (has {sorted(up_got)}, wanted {sorted(up_want)})"
    want, got = tree(os.path.join(HERE, "setup/local/www")), tree(dest, skip="uploads")
    missing, extra = sorted(set(want) - set(got)), sorted(set(got) - set(want))
    differ = sorted(p for p in set(want) & set(got) if want[p][0] != got[p][0])
    modes = sorted(p for p in set(want) & set(got) if want[p][1] != got[p][1])
    if missing or extra or differ or modes:
        return False, f"missing {missing}, left over {extra}, contents differ {differ}, executable bit wrong {modes}"
    return True, "~/www matches the local site and the uploads are untouched"
