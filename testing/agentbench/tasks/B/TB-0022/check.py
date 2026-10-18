import os

WANT = {
    "auth.conf": "ok", "auth defaults.conf": "invalid", "billing.conf": "crash", "cache.conf": "invalid",
    "core (staging).conf": "invalid", "edge eu-west.conf": "ok", "gateway.conf": "crash",
    "jobs-common.conf": "hang", "jobs.conf": "hang", "mail.conf": "crash", "metrics (old).conf": "invalid",
    "search.conf": "crash", "web.conf": "ok",
}


def remote_procs(remote, word):
    """Pids of live processes started on the remote (HOME is the remote) whose command line has WORD."""
    out = []
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            env = open(f"/proc/{pid}/environ", "rb").read().split(b"\0")
            cmd = open(f"/proc/{pid}/cmdline", "rb").read()
            st = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()[0]
        except OSError:
            continue
        if f"HOME={remote}".encode() in env and word.encode() in cmd and st != "Z":
            out.append(int(pid))
    return out


def check(local, remote):
    left = remote_procs(remote, "validate-cfg")
    if left:
        return False, f"validate-cfg is still running (pids {left})"
    path = os.path.join(local, "report.txt")
    if not os.path.exists(path):
        return False, "no report.txt"
    got = {}
    for line in open(path, encoding="utf-8", errors="replace").read().splitlines():
        if not line.strip():
            continue
        name, sep, outcome = line.rpartition(":")
        if not sep:
            return False, f"line without 'NAME: OUTCOME': {line!r}"
        got[name.strip()] = outcome.strip().lower()
    wrong = {n: (got.get(n), w) for n, w in WANT.items() if got.get(n) != w}
    extra = sorted(set(got) - set(WANT))
    if wrong or extra:
        return False, f"wrong (got, wanted): {wrong}; unknown names: {extra}"
    return True, "all 13 configs classified correctly"
