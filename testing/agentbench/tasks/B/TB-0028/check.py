import hashlib
import os
import random


def check(local, remote):
    path = os.path.join(local, "snapshot.bin")
    if not os.path.exists(path):
        return False, "no snapshot.bin in the local directory"
    rng = random.Random(2828)
    want = hashlib.sha256()
    for _ in range(40):
        want.update(rng.randbytes(1 << 20))
    got = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            got.update(chunk)
    size = os.path.getsize(path)
    if got.hexdigest() != want.hexdigest():
        return False, f"snapshot.bin differs from the export ({size} bytes, wanted {40 << 20})"
    return True, "the snapshot arrived intact"
