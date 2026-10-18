import os


def check(local, remote):
    if not os.path.exists(os.path.join(remote, ".bench", "import.ran")):
        return False, "import-scene never ran"
    want = ["KeyError: 'navmesh_bounds'", "1"]
    path = os.path.join(local, "answer.txt")
    got = [l.strip() for l in open(path).read().splitlines() if l.strip()] if os.path.exists(path) else None
    return got == want, f"answer {got!r}, wanted {want!r}"
