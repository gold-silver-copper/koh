import hashlib, json, os, random, struct


def check(local, remote):
    h = hashlib.sha256(b"DSET" + struct.pack("<I", 32))
    for shard in range(32):
        h.update(random.Random(880 + shard).randbytes(1 << 20))
    want = h.hexdigest()
    path = os.path.join(remote, "data", "incoming", "dataset.bin")
    if not os.path.exists(path):
        return False, "no ~/data/incoming/dataset.bin on the remote"
    got = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            got.update(chunk)
    if got.hexdigest() != want:
        return False, f"~/data/incoming/dataset.bin ({os.path.getsize(path)} bytes) differs from the dataset"
    rec = os.path.join(remote, ".bench", "registry.json")
    regs = [json.loads(l) for l in open(rec)] if os.path.exists(rec) else []
    if not any(r["sha256"] == want and r["path"] == os.path.realpath(path) or r["sha256"] == want for r in regs):
        return False, "the dataset was never registered with register-dataset"
    return True, "dataset uploaded and registered"
