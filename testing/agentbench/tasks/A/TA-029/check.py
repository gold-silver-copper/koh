import os
import json


def read(path):
    try:
        with open(path, errors="replace") as f:
            return f.read()
    except OSError:
        return None


def readb(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError:
        return None


def alive(pid):
    try:
        with open(f"/proc/{int(pid)}/stat") as f:
            return f.read().rsplit(")", 1)[1].split()[0] not in ("Z", "X")
    except (OSError, ValueError, IndexError):
        return False


def fixture(name, side="remote/bin"):
    """The task's own copy of a fixture, loaded as a module (its main guarded)."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "setup", *side.split("/"), name)
    ns = {"__name__": "fixture", "__file__": path}
    with open(path) as f:
        exec(compile(f.read(), path, "exec"), ns)
    return ns


import stat
DIST = [('bin', 'dir', 493, None), ('bin/ledgerd', 'file', 493, '#!/bin/sh\necho ledgerd 4.12\n'), ('bin/ledger-cli', 'file', 488, '#!/bin/sh\necho ledger-cli\n'), ('bin/ledger', 'link', None, 'ledgerd'), ('etc', 'dir', 493, None), ('etc/ledgerd.conf', 'file', 420, 'listen = 127.0.0.1:7000\n'), ('etc/secret.key', 'file', 384, 'k3y-0f-the-ledger\n'), ('share', 'dir', 493, None), ('share/doc', 'dir', 493, None), ('share/doc/README (copy).txt', 'file', 420, 'Read me.\n'), ('share/doc/notes for v4.12 – draft.md', 'file', 420, '# Notes\n'), ('share/doc/-leading-dash.txt', 'file', 292, 'dash\n'), ('share/doc/it\'s "quoted" $X.txt', 'file', 420, 'quotes\n'), ('current-docs', 'link', None, 'share/doc'), ('var', 'dir', 448, None), ('var/state.db', 'file', 416, 'STATE\x00\x01\x02\n'), ('var/run', 'dir', 488, None), ('var/run/.pidfile-placeholder', 'file', 384, '')]
def check(local, remote):
    if not os.path.isdir(os.path.join(remote, "dist")):
        return False, "~/bin/package was never run"
    root = os.path.join(local, "dist")
    if not os.path.isdir(root):
        return False, "local dist/ missing"
    want = {p for p, *_ in DIST}
    have = set()
    for d, dirs, files in os.walk(root):
        for n in dirs + files:
            have.add(os.path.relpath(os.path.join(d, n), root))
    if have != want:
        return False, f"dist/ has extra {sorted(have - want)[:5]} and lacks {sorted(want - have)[:5]}"
    for p, kind, mode, data in DIST:
        full = os.path.join(root, p)
        st = os.lstat(full)
        if kind == "link":
            if not stat.S_ISLNK(st.st_mode) or os.readlink(full) != data:
                return False, f"dist/{p} should be a symlink to {data!r}"
            continue
        if kind == "dir" and not stat.S_ISDIR(st.st_mode) or kind == "file" and not stat.S_ISREG(st.st_mode):
            return False, f"dist/{p} should be a {kind}"
        if stat.S_IMODE(st.st_mode) != mode:
            return False, f"dist/{p} has mode {oct(stat.S_IMODE(st.st_mode))}, wanted {oct(mode)}"
        if kind == "file" and readb(full) != data.encode():
            return False, f"dist/{p} content differs"
    return True, "dist/ copied exactly"
