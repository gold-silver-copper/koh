import os

HERE = os.path.dirname(os.path.abspath(__file__))
NAME = "Q3 summary (final) – v2.pdf"


def check(local, remote):
    want = open(os.path.join(HERE, "setup/remote/reports", NAME), "rb").read()
    path = os.path.join(local, NAME)
    if not os.path.exists(path):
        return False, f"no {NAME!r} in the local directory (found {sorted(os.listdir(local))!r})"
    got = open(path, "rb").read()
    return got == want, "the report was copied intact" if got == want else f"the local copy differs ({len(got)} bytes, wanted {len(want)})"
