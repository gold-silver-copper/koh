import hashlib
import os

HERE = os.path.dirname(os.path.abspath(__file__))
HEADER = "# managed by edit-hosts; checksum="


def check(local, remote):
    path = os.path.join(remote, "etc", "hosts")
    if not os.path.exists(path):
        return False, "~/etc/hosts is gone"
    lines = open(path).read().splitlines()
    orig = open(os.path.join(HERE, "setup/remote/etc/hosts")).read().splitlines()
    if not lines or not lines[0].startswith(HEADER):
        return False, "~/etc/hosts lost its edit-hosts header (edited behind edit-hosts' back?)"
    body = lines[1:]
    if lines[0][len(HEADER):] != hashlib.sha256(("\n".join(body) + "\n").encode()).hexdigest()[:16]:
        return False, "~/etc/hosts was changed outside edit-hosts (its checksum doesn't match)"
    want = []
    for l in orig[1:]:
        if "old-db.internal" in l:
            continue
        want.append(l.split())
        if "cache-1.internal" in l:
            want.append(["10.0.4.7", "cache-2.internal", "cache-2"])
    got = [l.split() for l in body if l.strip()]
    if got != want:
        return False, f"hosts entries are {[' '.join(x) for x in got]}, wanted {[' '.join(x) for x in want]}"
    return True, "hosts edited through edit-hosts"
