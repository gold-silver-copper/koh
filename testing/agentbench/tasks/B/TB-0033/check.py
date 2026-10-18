import hashlib
import os
import stat


def tree(root):
    out = {}
    for d, dirs, files in os.walk(root):
        for f in files:
            p = os.path.join(d, f)
            h = hashlib.sha256(open(p, "rb").read()).hexdigest() if os.access(p, os.R_OK) else "unreadable"
            out[os.path.relpath(p, root)] = (h, stat.S_IMODE(os.lstat(p).st_mode))
    return out


def check(local, remote):
    src = os.path.join(remote, "db")
    if not os.path.isdir(src):
        return False, "~/db was never seeded"
    want = tree(src)
    if len(want) < 1700 or "wal/000000010000000A.wal" not in want:
        return False, f"~/db on the remote is not the seeded database any more ({len(want)} files)"
    dest = os.path.join(local, "db-backup")
    if not os.path.isdir(dest):
        return False, "no db-backup/ in the local directory"
    got = tree(dest)
    missing, extra = sorted(set(want) - set(got)), sorted(set(got) - set(want))
    differ = sorted(p for p in set(want) & set(got) if want[p][0] != got[p][0])
    modes = sorted(p for p in set(want) & set(got) if want[p][1] != got[p][1])
    if missing or extra or differ or modes:
        return False, (f"{len(missing)} missing (e.g. {missing[:3]}), {len(extra)} extra, {len(differ)} differ "
                       f"(e.g. {differ[:3]}), {len(modes)} with wrong permissions (e.g. {modes[:3]})")
    return True, f"db-backup is an exact copy ({len(want)} files)"
