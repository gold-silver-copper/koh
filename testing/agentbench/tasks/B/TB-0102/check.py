import json, os


def check(local, remote):
    st = json.load(open(os.path.join(remote, "server", "players.json")))
    want = {"xX_Sn1per_Xx", "Big Tony", "ñandú"}
    if st["banned"]:
        return False, f"banned {st['banned']}; nobody should be banned"
    if set(st["kicked"]) != want or len(st["kicked"]) != len(want):
        return False, f"saved state has kicked {st['kicked']}, wanted {sorted(want)}"
    if not os.path.exists(os.path.join(remote, ".bench", "console.quit")):
        return False, "the console was never left with `quit`"
    return True, "the three speedhackers were kicked and the state saved"
