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


WANT = ["70", 'FATAL: shard 12 manifest truncated at byte 88123']
def check(local, remote):
    if read(os.path.join(remote, ".ingest-ran")) is None:
        return False, "ingest was never run to the end"
    got = read(os.path.join(local, "answer.txt"))
    if got is None:
        return False, "answer.txt missing"
    lines = [l.strip() for l in got.strip().splitlines()]
    return lines == WANT, f"answer {lines!r}, wanted {WANT!r}"
