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


import hashlib
KEY = 'O\'Brien & Sons "Ltd" $HOME\\n #1;`date`'
WANT = hashlib.sha256(("acct:" + KEY).encode()).hexdigest()[:12]
def check(local, remote):
    got = read(os.path.join(local, "answer.txt"))
    got = got.strip() if got is not None else None
    calls = [json.loads(l) for l in (read(os.path.join(remote, ".lookup-calls")) or "").splitlines() if l.strip()]
    if not any(c.get("matched") for c in calls):
        seen = [c.get("arg") for c in calls][-3:]
        return False, f"lookup never got the exact name; it got {seen!r}"
    return got == WANT, f"answer {got!r}, wanted {WANT!r}"
