import hashlib, os


def check(local, remote):
    dump = os.path.join(remote, "dumps", "nightly.sql.gz")
    if not os.path.exists(dump):
        return False, "the dump never completed"
    want = hashlib.sha256(open(dump, "rb").read()).hexdigest()
    path = os.path.join(local, "answer.txt")
    got = open(path).read().strip() if os.path.exists(path) else None
    return got == want, f"answer {got!r}, wanted {want!r}"
