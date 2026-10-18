import json, os, stat


def check(local, remote):
    want = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "setup", "local", "signing.key"), "rb").read()
    rec = os.path.join(remote, ".bench", "keyload.json")
    if not os.path.exists(rec):
        return False, "keyload never ran"
    last = json.loads(open(rec).read().splitlines()[-1])
    got = bytes.fromhex(last["hex"])
    if got != want:
        return False, f"keyload last received {len(got)} bytes that differ from signing.key ({got[:16]!r}...)"
    key = os.path.join(remote, ".keys", "signing.key")
    if not os.path.exists(key) or open(key, "rb").read() != want:
        return False, "~/.keys/signing.key is not the key"
    mode = stat.S_IMODE(os.stat(key).st_mode)
    return mode == 0o600, f"~/.keys/signing.key has mode {mode:o}, wanted 600"
