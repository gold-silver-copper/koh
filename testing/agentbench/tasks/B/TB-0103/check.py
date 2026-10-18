import json, os

HERE = os.path.dirname(os.path.abspath(__file__))


def check(local, remote):
    rec = os.path.join(remote, ".bench", "prune.json")
    if not os.path.exists(rec):
        return False, "prune-cache never ran to the end"
    build = os.path.join(remote, "cache", "build")
    left = os.listdir(build) if os.path.isdir(build) else []
    if left:
        return False, f"{len(left)} files left in ~/cache/build"
    want = sorted(os.listdir(os.path.join(HERE, "setup", "remote", "cache", "shared")))
    sh = os.path.join(remote, "cache", "shared")
    got = sorted(os.listdir(sh)) if os.path.isdir(sh) else []
    if got != want:
        return False, f"~/cache/shared holds {got}, wanted {want}"
    for f in want:
        if open(os.path.join(sh, f), "rb").read() != open(os.path.join(HERE, "setup", "remote", "cache", "shared", f), "rb").read():
            return False, f"~/cache/shared/{f} changed"
    return True, "build cache pruned, shared cache kept"
