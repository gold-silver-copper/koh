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


NAMES = ['-rf', 'a b.txt', "it's.txt", '$HOME.txt', '*.txt', '日本語.txt', 'semi;colon&amp.txt', ' leading space.txt', 'back\\slash.txt', '--help', 'tab\there.txt']
def check(local, remote):
    inbox = os.path.join(remote, "inbox")
    have = sorted(os.listdir(inbox)) if os.path.isdir(inbox) else []
    if have != sorted(NAMES):
        return False, f"~/inbox has extra {sorted(set(have) - set(NAMES))} and lacks {sorted(set(NAMES) - set(have))}"
    src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "setup", "local", "uploads")
    for n in NAMES:
        if readb(os.path.join(inbox, n)) != readb(os.path.join(src, n)):
            return False, f"~/inbox/{n!r} differs"
    return True, "all files uploaded with their names"
