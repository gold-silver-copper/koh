import os


def check(local, remote):
    state = os.path.join(remote, ".rebuild-catalog")
    starts = open(os.path.join(state, "starts")).read().split() if os.path.exists(os.path.join(state, "starts")) else []
    if not starts:
        return False, "rebuild-catalog was never run"
    if len(starts) > 1:
        return False, f"rebuild-catalog was started {len(starts)} times; it had to run once"
    if not os.path.exists(os.path.join(state, "done")):
        return False, "rebuild-catalog never finished"
    want = open(os.path.join(state, "done")).read().strip()
    path = os.path.join(local, "digest.txt")
    got = open(path).read().strip() if os.path.exists(path) else None
    return got == want, f"digest {got!r}, wanted {want!r}"
