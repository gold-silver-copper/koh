import csv
import hashlib
import os


def check(local, remote):
    src = os.path.join(local, "orders.csv")
    rec = os.path.join(remote, ".tally", "last-input.sha256")
    if not os.path.exists(rec):
        return False, "tally was never run"
    data = open(src, "rb").read()
    if open(rec).read().strip() != hashlib.sha256(data).hexdigest():
        return False, "the last input tally read was not the contents of orders.csv"
    want = f"{sum(float(r['amount']) for r in csv.DictReader(open(src))):.2f}"
    path = os.path.join(local, "answer.txt")
    got = open(path).read().strip() if os.path.exists(path) else None
    return got == want, f"answer {got!r}, wanted {want!r}"
