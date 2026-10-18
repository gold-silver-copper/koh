import hashlib, json, os


def check(local, remote):
    want = hashlib.sha256(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "setup", "local", "firmware.img"), "rb").read()).hexdigest()
    rec = os.path.join(remote, ".bench", "flash.json")
    if not os.path.exists(rec):
        return False, "flash-device never ran"
    last = json.loads(open(rec).read().splitlines()[-1])
    if last["sha256"] != want:
        return False, f"the last flash read {last['bytes']} bytes that are not firmware.img"
    return True, "flashed with firmware.img"
