import json, os, zlib

R = ["common", "uncommon", "rare", "epic", "legendary"]


def check(local, remote):
    if not os.path.exists(os.path.join(remote, ".bench", "invsh.ran")):
        return False, "invsh was never used"
    items = json.loads(zlib.decompress(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "setup", "remote", "inventory.db"), "rb").read()))
    want = str(sum(1 for x in items if x["category"] == "potions" and R.index(x["rarity"]) >= 3))
    path = os.path.join(local, "answer.txt")
    got = open(path).read().strip() if os.path.exists(path) else None
    return got == want, f"answer {got!r}, wanted {want!r}"
