import datetime
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))


def check(local, remote):
    today = datetime.date(2026, 10, 17)
    names = os.listdir(os.path.join(HERE, "setup/remote/builds"))
    old = {n for n in names if (today - datetime.date.fromisoformat(re.match(r"build-(.{10})", n).group(1))).days > 30}
    d = os.path.join(remote, "builds")
    now = set(os.listdir(d)) - {".pruned"} if os.path.isdir(d) else set()
    if not os.path.exists(os.path.join(d, ".pruned")):
        return False, "prune-builds never completed a deletion"
    if now & old:
        return False, f"old builds still there: {sorted(now & old)}"
    if (set(names) - old) - now:
        return False, f"recent builds were deleted: {sorted((set(names) - old) - now)}"
    return True, f"{len(old)} old builds pruned, recent ones kept"
