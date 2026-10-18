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


import sqlite3
def check(local, remote):
    db = sqlite3.connect(":memory:")
    fixture("dbshell")["build"](db)
    want = db.execute("select c.name from customers c join orders o on o.customer_id = c.id "
                      "where o.placed like '2025-%' group by c.id order by sum(o.amount) desc limit 1").fetchone()[0]
    got = read(os.path.join(local, "answer.txt"))
    got = got.strip() if got is not None else None
    return got == want, f"answer {got!r}, wanted {want!r}"
