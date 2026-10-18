import hashlib
import json
import os

WANT = 'it\'s "v2.0" $HOME *'


def check(local, remote):
    tag = hashlib.sha256(WANT.encode()).hexdigest()[:12]
    calls = []
    log = os.path.join(remote, ".tagger", "calls.jsonl")
    if os.path.exists(log):
        calls = [json.loads(l) for l in open(log) if l.strip()]
    if [WANT] not in calls:
        last = calls[-1] if calls else None
        return False, f"tagger never got the one argument {WANT!r} (last call's arguments: {last!r})"
    path = os.path.join(local, "answer.txt")
    got = open(path).read().strip() if os.path.exists(path) else None
    return got == tag, f"answer {got!r}, wanted {tag!r}"
