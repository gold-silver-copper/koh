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


SITE = {k: v[1] for k, v in {'index.html': ('<!doctype html>\n<title>Ledger</title>\n<h1>Ledger</h1>\n', 420), 'about us.html': ('<!doctype html>\n<title>About us</title>\n', 420), '.htaccess': ('Options -Indexes\nDirectoryIndex index.html\n', 420), 'css/main.css': ('body { font: 16px/1.4 sans-serif; }\n', 420), 'img/logo.svg': ('<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"/>\n', 420), 'cgi-bin/stats.cgi': ("#!/bin/sh\necho 'Content-Type: text/plain'\necho\necho ok\n", 493), 'deploy.sh': ('#!/bin/sh\nset -e\necho deploying\n', 493), 'data/uploads/.keep': ('', 420)}.items()}
def check(local, remote):
    src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "setup", "local", "site")
    dst = os.path.join(remote, "www", "site")
    for rel, mode in SITE.items():
        p = os.path.join(dst, rel)
        if not os.path.isfile(p):
            return False, f"~/www/site/{rel} missing"
        if readb(p) != readb(os.path.join(src, rel)):
            return False, f"~/www/site/{rel} differs"
        if bool(os.stat(p).st_mode & 0o111) != bool(mode & 0o111):
            return False, f"~/www/site/{rel} has mode {oct(os.stat(p).st_mode & 0o777)}, wanted executable={bool(mode & 0o111)}"
    return True, "site copied with its modes"
