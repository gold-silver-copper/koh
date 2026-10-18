import os

HERE = os.path.dirname(os.path.abspath(__file__))


def check(local, remote):
    want = open(os.path.join(HERE, "setup/remote/data/orders.csv")).read().split("\n")[1337]
    path = os.path.join(local, "bad-row.txt")
    got = open(path).read().strip("\r\n") if os.path.exists(path) else None
    return got == want, f"bad-row.txt has {got!r}, wanted {want!r}"
