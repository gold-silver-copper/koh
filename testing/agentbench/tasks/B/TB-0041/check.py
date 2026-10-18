import os


def r3_at_mix(hit):
    """r3 when execution reaches `mix` for the HIT-th time (simulated independently of vmdbg)."""
    r1, r2, r3, r4, n = 7, 0, 1, 24, 0
    while True:
        r1 = (r1 * 1103 + 12345) % 65521
        if r1 % 7 != 0:
            n += 1
            if n == hit:
                return r3
            r3 = ((r3 ^ r1) * 31 + r2) % 1000003
        r2 = (r2 + r1) % 99991
        r4 -= 1
        if r4 == 0:
            return None


def check(local, remote):
    want = str(r3_at_mix(5))
    path = os.path.join(local, "answer.txt")
    got = open(path).read().strip() if os.path.exists(path) else None
    if got == str(r3_at_mix(6)) or got == str(r3_at_mix(4)):
        return False, f"answer {got!r} is r3 at a neighbouring hit of mix, wanted {want!r} (the 5th)"
    return got == want, f"answer {got!r}, wanted {want!r}"
