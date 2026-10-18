import hashlib
import os


def check(local, remote):
    d = os.path.join(remote, ".vault")
    if os.path.exists(os.path.join(d, "lockout")):
        return False, "the vault got locked out after three wrong passphrases"
    if not os.path.exists(os.path.join(d, "unlocked")):
        return False, "the vault was never unlocked"
    p = open(os.path.join(local, "passphrase.txt")).read().rstrip("\n")
    code = hashlib.sha256(b"session" + p.encode()).hexdigest()[:8].upper()
    want = code[:4] + "-" + code[4:]
    path = os.path.join(local, "answer.txt")
    got = open(path).read().strip() if os.path.exists(path) else None
    return got == want, f"answer {got!r}, wanted {want!r}"
