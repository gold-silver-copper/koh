import json
import os
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))


def check(local, remote):
    path = os.path.join(remote, "team.board")
    try:
        data = json.load(open(path))
        columns = data["columns"]
    except (OSError, ValueError, KeyError) as e:
        return False, f"~/team.board is unreadable: {e}"
    if data.get("crc") != zlib.crc32(json.dumps(columns, sort_keys=True).encode()):
        return False, "~/team.board fails its checksum (it was changed outside board)"
    orig = json.load(open(os.path.join(HERE, "setup/remote/team.board")))["columns"]
    if data.get("saved_at") == "2026-10-16T17:02:11":
        return False, "the board was never saved"
    want = {c: list(v) for c, v in orig.items()}
    want["Doing"].remove("Rotate TLS certs")
    want["Backlog"].remove("Upgrade postgres to 17")
    for c, card in (("Done", "Rotate TLS certs"), ("Doing", "Upgrade postgres to 17")):
        if card not in columns.get(c, []):
            return False, f"{card!r} is not in {c}: board is {columns}"
    got = {c: [x for x in v if x not in ("Rotate TLS certs", "Upgrade postgres to 17")] for c, v in columns.items()}
    if got != want:
        return False, f"other cards moved: board is {columns}"
    return True, "both cards moved and the board saved"
