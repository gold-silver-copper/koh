import json, os


def check(local, remote):
    rec = os.path.join(remote, ".bench", "journal.json")
    if not os.path.exists(rec):
        return False, "dump-journal never ran to the end"
    rec = json.load(open(rec))
    want = [str(rec["total"]), rec["top"]]
    path = os.path.join(local, "answer.txt")
    got = [l.strip() for l in open(path).read().splitlines() if l.strip()] if os.path.exists(path) else None
    return got == want, f"answer {got!r}, wanted {want!r}"
