import json, os


def check(local, remote):
    want = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "setup", "local", "tag.txt")).read().rstrip("\n")
    for d, _, files in os.walk(remote):
        if "PWNED" in files:
            return False, f"the text ran as a command: {os.path.join(d, 'PWNED')} exists"
    rec = os.path.join(remote, ".bench", "argv.json")
    if not os.path.exists(rec):
        return False, "tag-release never ran"
    calls = [json.loads(l) for l in open(rec) if l.strip()]
    last = calls[-1]
    return last == [want], f"last call's arguments {last!r}, wanted {[want]!r}"
