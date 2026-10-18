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


import subprocess, tempfile, shutil
MAIN = None
def git(repo, *a):
    return subprocess.run(["git", "--git-dir", repo, *a], capture_output=True, text=True)
def check(local, remote):
    repo = os.path.join(remote, "git", "ledger-retry.git")
    main = git(repo, "rev-parse", "main").stdout.strip()
    orig = os.path.join(os.path.dirname(os.path.abspath(__file__)), "setup", "remote", "git", "ledger-retry.git", "refs", "heads", "main")
    if main != open(orig).read().strip():
        return False, "main was changed"
    if git(repo, "merge-base", "--is-ancestor", "main", "feature/retry").returncode != 0:
        return False, "feature/retry is not on top of main"
    merges = git(repo, "rev-list", "--merges", "main..feature/retry").stdout.split()
    if merges:
        return False, "feature/retry has merge commits; it should be rebased"
    if not git(repo, "rev-list", "main..feature/retry").stdout.split():
        return False, "feature/retry has no commits of its own on top of main"
    tmp = tempfile.mkdtemp(dir=remote, prefix=".check-")
    try:
        arch = subprocess.run(["git", "--git-dir", repo, "archive", "feature/retry"], capture_output=True)
        subprocess.run(["tar", "-x", "-C", tmp], input=arch.stdout, check=True)
        tests = read(os.path.join(tmp, "test_retry.py")) or ""
        for name in ("test_succeeds_eventually", "test_raises_after_all_tries", "test_backoff_doubles",
                     "test_other_errors_not_retried"):
            if f"def {name}" not in tests:
                return False, f"the test {name} is gone"
        r = subprocess.run(["python3", "-m", "unittest", "-q"], cwd=tmp, capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            return False, "the tests fail on feature/retry: " + r.stderr[-300:]
        probe = (
            "from retry import retry\n"
            "w = []\n"
            "n = {'k': 0}\n"
            "def f():\n"
            "    n['k'] += 1\n"
            "    if n['k'] < 3: raise ValueError()\n"
            "    return 7\n"
            "assert retry(f, tries=3, exceptions=(ValueError,), delay=1, sleep=w.append) == 7, 'result'\n"
            "assert w == [1, 2], w\n"
            "def g(): raise KeyError()\n"
            "try:\n"
            "    retry(g, tries=3, exceptions=(ValueError,), delay=1, sleep=w.append)\n"
            "except KeyError: pass\n"
            "assert w == [1, 2], 'a KeyError was retried'\n"
        )
        r = subprocess.run(["python3", "-c", probe], cwd=tmp, capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            return False, "retry() does not combine tries, exceptions and backoff: " + r.stderr[-300:]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return True, "feature/retry rebased onto main, both changes kept, tests pass"
