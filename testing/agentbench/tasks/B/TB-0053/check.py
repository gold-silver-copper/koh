import os


def check(local, remote):
    if not os.path.exists(os.path.join(remote, ".gate", "granted")):
        return False, "gatekeeper never granted access"
    d = os.path.join(remote, ".tokens")
    try:
        pid = int(open(os.path.join(d, "pid")).read())
        st = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()[0]
        if st != "Z":
            return False, "token-server is still running"
    except (OSError, ValueError):
        pass
    if not os.path.exists(os.path.join(d, "stopped")):
        return False, "token-server did not stop cleanly (killed outright, or still running)"
    return True, f"access granted and token-server stopped cleanly ({open(os.path.join(d, 'stopped')).read().strip()})"
