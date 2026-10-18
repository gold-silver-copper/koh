import os

WANT = "Arch Linux (linux-lts 6.6.54, fallback initramfs)"


def check(local, remote):
    conf = os.path.join(remote, "boot", "default.conf")
    if not os.path.exists(conf):
        return False, "~/boot/default.conf is gone"
    lines = open(conf).read().splitlines()
    got = [l.split("=", 1)[1] for l in lines if l.startswith("default=")]
    if got != [WANT]:
        return False, f"default is {got!r}, wanted {WANT!r}"
    if "timeout=5" not in lines:
        return False, "the other settings in default.conf were lost"
    return True, "the default boot entry is set"
