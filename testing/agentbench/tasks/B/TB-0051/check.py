import os


def check(local, remote):
    if not os.path.exists(os.path.join(remote, ".pair", "session.json")):
        return False, "pair-device was never run"
    if not os.path.exists(os.path.join(remote, ".pair", "paired.json")):
        return False, "the sensor was never paired"
    return True, "pair-device confirmed the pairing"
