import hashlib, json, os, random, struct


def check(local, remote):
    body = b"".join(random.Random(1090 + i).randbytes(1 << 20) for i in range(24))
    want = hashlib.sha256(b"CAPT" + struct.pack("<Q", len(body)) + hashlib.sha256(body).digest() + body).hexdigest()
    p = os.path.join(remote, "captures", "cap.bin")
    if not os.path.exists(p):
        return False, "receive-capture never stored a complete capture"
    if hashlib.sha256(open(p, "rb").read()).hexdigest() != want:
        return False, "~/captures/cap.bin is not the capture"
    rec = os.path.join(remote, ".bench", "receive.json")
    if not os.path.exists(rec) or not json.loads(open(rec).read().splitlines()[-1])["ok"]:
        return False, "receive-capture did not accept it last"
    return True, "capture received and accepted"
