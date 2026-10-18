import hashlib
import os
import struct


def check(local, remote):
    data = open(os.path.join(local, "firmware.bin"), "rb").read()
    rec = os.path.join(remote, ".flash", "received.log")
    if not os.path.exists(rec):
        return False, "flash was never run"
    got_sha = hashlib.sha256(data).hexdigest()
    if not any(l.split()[1:] == [got_sha] for l in open(rec) if l.strip()):
        sizes = [l.split()[0] for l in open(rec) if l.strip()]
        return False, f"flash never received firmware.bin intact (received sizes {sizes}, wanted {len(data)})"
    crc = struct.unpack("<II", data[8:16])[1]
    want = f"{crc:08x}-{hashlib.sha256(data[16:]).hexdigest()[:8]}"
    path = os.path.join(local, "answer.txt")
    got = open(path).read().strip() if os.path.exists(path) else None
    return got == want, f"answer {got!r}, wanted {want!r}"
