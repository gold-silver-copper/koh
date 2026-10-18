import hashlib, json, os


def check(local, remote):
    want = hashlib.sha256(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "setup", "local", "orders.csv"), "rb").read()).hexdigest()
    rec = os.path.join(remote, ".bench", "ingest.json")
    if not os.path.exists(rec):
        return False, "ingest-orders never ran"
    last = json.loads(open(rec).read().splitlines()[-1])
    if not os.path.exists(os.path.join(remote, "ingest", "summary.txt")):
        return False, "no ~/ingest/summary.txt"
    return last["sha256"] == want, f"ingest-orders last read {last['bytes']} bytes " + ("matching orders.csv" if last["sha256"] == want else "that differ from orders.csv")
