import json
import os


def check(local, remote):
    d = os.path.join(remote, ".db-upgrade")
    if os.path.exists(os.path.join(d, "done.json")):
        done = json.load(open(os.path.join(d, "done.json")))
        if done.get("version") != 60:
            return False, f"the upgrade stopped at version {done.get('version')} (answers {done.get('answers')})"
        if done.get("answers") != ["yes", "no"]:
            return False, f"answers were {done.get('answers')}, wanted ['yes', 'no']"
        return True, "upgraded to 60 with the right answers"
    if os.path.exists(os.path.join(d, "aborted.json")):
        return False, "the upgrade aborted: a question went unanswered"
    return False, "db-upgrade never finished"
