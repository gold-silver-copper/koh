import hashlib, os

HERE = os.path.dirname(os.path.abspath(__file__))


def tree(root, skip=None):
    out = {}
    for d, dirs, files in os.walk(root):
        rel = os.path.relpath(d, root)
        if skip and (rel == skip or rel.startswith(skip + os.sep)):
            continue
        if not files and not dirs and rel != ".":
            out[rel + "/"] = "dir"
        for f in files:
            p = os.path.join(d, f)
            out[os.path.relpath(p, root)] = hashlib.sha256(open(p, "rb").read()).hexdigest()
    return out


def check(local, remote):
    site = os.path.join(remote, "site")
    if not os.path.isdir(site):
        return False, "~/site is gone"
    want_up = tree(os.path.join(HERE, "setup", "remote", "site", "uploads"))
    got_up = tree(os.path.join(site, "uploads")) if os.path.isdir(os.path.join(site, "uploads")) else {}
    if want_up != got_up:
        return False, "~/site/uploads changed"
    want = tree(os.path.join(HERE, "setup", "local", "site"))
    got = tree(site, skip="uploads")
    missing = sorted(set(want) - set(got))
    extra = sorted(set(got) - set(want))
    wrong = sorted(k for k in set(want) & set(got) if want[k] != got[k])
    dirs = sorted(d for d in os.listdir(site) if os.path.isdir(os.path.join(site, d)) and d != "uploads"
                  and not os.path.isdir(os.path.join(HERE, "setup", "local", "site", d)))
    if missing or extra or wrong or dirs:
        return False, f"missing {missing}, extra {extra + dirs}, different {wrong}"
    return True, "~/site mirrors site/, uploads kept"
