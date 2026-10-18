import hashlib, json, os, zlib


def check(local, remote):
    rec = os.path.join(remote, ".bench", "export.json")
    if not os.path.exists(rec):
        return False, "export-db never finished"
    rec = json.load(open(rec))
    z = os.path.join(remote, "backup", "db.z")
    if not os.path.exists(z):
        return False, "no ~/backup/db.z"
    try:
        data = zlib.decompress(open(z, "rb").read())
    except zlib.error as e:
        return False, f"~/backup/db.z is not zpack output: {e}"
    if hashlib.sha256(data).hexdigest() != rec["sha256"]:
        return False, "~/backup/db.z does not hold what export-db wrote"
    path = os.path.join(local, "answer.txt")
    got = open(path).read().strip() if os.path.exists(path) else None
    return got == str(rec["status"]), f"answer {got!r}, wanted {str(rec['status'])!r}"
