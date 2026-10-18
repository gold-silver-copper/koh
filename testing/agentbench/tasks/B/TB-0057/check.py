import os


def alive(pid, word):
    try:
        st = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()[0]
        return st != "Z" and word in open(f"/proc/{pid}/cmdline", "rb").read()
    except OSError:
        return False


def check(local, remote):
    d = os.path.join(remote, ".app")
    if not os.path.exists(os.path.join(d, "appd.pid")):
        return False, "the app was never started"
    appd = int(open(os.path.join(d, "appd.pid")).read())
    flusher = int(open(os.path.join(d, "flusher.pid")).read())
    if not alive(appd, b"appd"):
        return False, "the app daemon (appd) is not running any more"
    if alive(flusher, b"app-flusher"):
        return False, "the debug log writer (app-flusher) is still running"
    log = os.path.join(remote, "app", "logs", "debug.log")
    size = os.path.getsize(log) if os.path.exists(log) else 0
    if size >= 1 << 20:
        return False, f"debug.log is still {size >> 20} MB"
    return True, "the writer is stopped, appd is up, and debug.log is small"
