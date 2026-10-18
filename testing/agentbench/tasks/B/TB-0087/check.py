import hashlib, os, random


def check(local, remote):
    h = hashlib.sha256(b"PAK1\x00\x01\x04\x02")
    for i in range(48):
        h.update(random.Random(8700 + i).randbytes(1 << 20))
    path = os.path.join(local, "game-1.4.2.pak")
    if not os.path.exists(path):
        return False, "no game-1.4.2.pak in the local directory"
    got = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            got.update(chunk)
    return got.hexdigest() == h.hexdigest(), f"local game-1.4.2.pak is {os.path.getsize(path)} bytes, " + ("identical" if got.hexdigest() == h.hexdigest() else "not identical to the package")
