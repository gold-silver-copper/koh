import hashlib
import os


def check(local, remote):
    done = os.path.join(remote, ".bootstrap", "done")
    if not os.path.exists(done):
        return False, "bootstrap never completed on the remote"
    want = open(done).read().strip()
    path = os.path.join(local, "password.txt")
    if not os.path.exists(path):
        return False, "no password.txt"
    got = open(path).read().strip()
    if hashlib.sha256(got.encode()).hexdigest() == want:
        return True, "the password matches"
    return False, f"password.txt has {got[:60]!r}, which is not the password bootstrap showed"
