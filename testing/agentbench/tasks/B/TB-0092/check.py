import hashlib, os, shutil, stat, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))


def describe(root):
    out = {}
    for d, dirs, files in os.walk(root):
        for name in dirs + files:
            p = os.path.join(d, name)
            rel = os.path.relpath(p, root)
            if os.path.islink(p):
                out[rel] = ("link", os.readlink(p))
            elif os.path.isdir(p):
                out[rel] = ("dir",)
            else:
                h = hashlib.sha256()
                with open(p, "rb") as f:
                    for chunk in iter(lambda: f.read(1 << 20), b""):
                        h.update(chunk)
                out[rel] = ("file", h.hexdigest(), bool(os.lstat(p).st_mode & stat.S_IXUSR))
    return out


def check(local, remote):
    root = os.path.join(local, "backup", "project")
    if not os.path.isdir(root):
        return False, "no backup/project locally"
    ref = os.path.join(remote, ".bench", "ref-home")
    shutil.rmtree(ref, ignore_errors=True)
    os.makedirs(ref)
    subprocess.run([sys.executable, os.path.join(HERE, "setup", "remote", "bin", "checkout-project")],
                   env=dict(os.environ, HOME=ref), check=True, capture_output=True)
    want = describe(os.path.join(ref, "project"))
    got = describe(root)
    shutil.rmtree(ref, ignore_errors=True)
    bad = []
    for k, v in sorted(want.items()):
        if k not in got:
            bad.append(f"{k} missing")
        elif got[k] != v:
            bad.append(f"{k}: {got[k][0]} {got[k][1:] if got[k][0] == 'link' else ''} instead of {v[0]} {v[1:] if v[0] == 'link' else ''}".strip())
    bad += [f"{k} extra" for k in sorted(got) if k not in want]
    return not bad, "; ".join(bad[:8]) or f"all {len(want)} entries match"
