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


import subprocess, sys
def check(local, remote):
    got = readb(os.path.join(local, "report.csv"))
    if got is None:
        return False, "report.csv missing"
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "setup", "remote", "bin", "render")
    want = subprocess.run([sys.executable, path], env={"REPORT_DATE": "2026-09-30", "PATH": "/usr/bin:/bin"},
                          capture_output=True, check=True).stdout
    if got == want:
        return True, "report.csv is byte-identical"
    if got.replace(b"\r\n", b"\n") == want:
        return False, "report.csv has CRLF line endings; render prints LF"
    return False, f"report.csv differs ({len(got)} bytes, wanted {len(want)}); first line {got[:80]!r}"
