#!/usr/bin/env python3
"""Seals a task set before it is used, and checks it when it is opened.

    python3 -I seal.py seal tasks/B     # tasks/B.ledger: a SHA-256 per task; tasks/B locked (chmod 000)
    python3 -I seal.py open tasks/B     # unlocked, and every task checked against the ledger
    python3 -I seal.py verify tasks/B   # the check alone, on an open set

A task's hash covers every file in its directory: relative paths and contents, in path order.
"""
import hashlib
import json
import os
import sys


def task_hash(path):
    h = hashlib.sha256()
    for root, dirs, files in os.walk(path):
        dirs[:] = sorted(d for d in dirs if d != "__pycache__")
        for name in sorted(files):
            full = os.path.join(root, name)
            h.update(os.path.relpath(full, path).encode() + b"\0")
            with open(full, "rb") as f:
                h.update(f.read() + b"\0")
    return h.hexdigest()


def hashes(folder):
    return {slug: task_hash(os.path.join(folder, slug)) for slug in sorted(os.listdir(folder))
            if os.path.isdir(os.path.join(folder, slug))}


def verify(folder):
    with open(folder.rstrip("/") + ".ledger") as f:
        ledger = json.load(f)
    now = hashes(folder)
    changed = sorted(k for k in ledger["tasks"] if now.get(k) != ledger["tasks"][k])
    added = sorted(set(now) - set(ledger["tasks"]))
    if changed or added:
        sys.exit(f"{folder}: changed {changed}, added {added}")
    print(f"{folder}: {len(now)} tasks match the ledger (set {ledger['set']})")


def main():
    cmd, folder = sys.argv[1], sys.argv[2].rstrip("/")
    if cmd == "seal":
        tasks = hashes(folder)
        whole = hashlib.sha256("".join(f"{k}:{v}\n" for k, v in tasks.items()).encode()).hexdigest()
        with open(folder + ".ledger", "w") as f:
            json.dump({"set": whole, "tasks": tasks}, f, indent=1)
        os.chmod(folder, 0)
        print(f"{folder}: {len(tasks)} tasks sealed, set {whole}")
    elif cmd == "open":
        os.chmod(folder, 0o755)
        verify(folder)
    elif cmd == "verify":
        verify(folder)
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
