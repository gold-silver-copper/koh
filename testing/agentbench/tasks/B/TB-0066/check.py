import os

WANT = ["cpu.governor", "gpu.vram", "license.server", "time.ntp"]


def check(local, remote):
    path = os.path.join(local, "answer.txt")
    if not os.path.exists(path):
        return False, "no answer.txt"
    got = [l.strip() for l in open(path).read().splitlines() if l.strip()]
    return got == WANT, f"answer {got!r}, wanted {WANT!r}"
