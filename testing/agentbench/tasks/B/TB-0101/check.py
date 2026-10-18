import json, os

KEY = b"vault-demo-key-0b7d"
RAW = "a3f5d1c47e2b9b0c8d6e5f40"


def check(local, remote):
    want = bytes(int(RAW[i:i + 2], 16) ^ KEY[(i // 2) % len(KEY)] for i in range(0, len(RAW), 2)).hex()
    rec = os.path.join(remote, ".bench", "vault.json")
    got_names = [json.loads(l)["got"] for l in open(rec)] if os.path.exists(rec) else []
    if "release/signing-pass" not in got_names:
        return False, "no authenticated vault session read release/signing-pass"
    path = os.path.join(local, "answer.txt")
    got = open(path).read().strip() if os.path.exists(path) else None
    return got == want, f"answer {got!r}, wanted {want!r}"
