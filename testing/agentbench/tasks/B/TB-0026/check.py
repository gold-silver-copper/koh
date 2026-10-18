import hashlib
import json
import os
import random


def check(local, remote):
    path = os.path.join(local, "summary.json")
    if not os.path.exists(path):
        return False, "no summary.json in the local directory"
    try:
        got = json.load(open(path))
    except ValueError as e:
        return False, f"summary.json is not JSON: {e}"
    if not got.get("valid"):
        return False, f"summarize.py found the stream invalid: {got.get('reason')}"
    want = hashlib.sha256(random.Random(2626).randbytes(12 * 2_000_000)).hexdigest()
    if got.get("sha256") != want or got.get("records") != 2_000_000:
        return False, "summary.json does not describe the stream emit-metrics writes"
    return True, "the stream arrived intact and was summarized"
