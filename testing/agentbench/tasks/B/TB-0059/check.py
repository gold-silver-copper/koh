import os

BAD = "b322d600526c72a63b640dcdbd20c50bc2d3f098"


def check(local, remote):
    path = os.path.join(local, "answer.txt")
    got = open(path).read().strip() if os.path.exists(path) else None
    if got and len(got) < 40 and BAD.startswith(got):
        return False, f"answer {got!r} is an abbreviated hash; the full hash was asked for"
    return got == BAD, f"answer {got!r}, wanted {BAD!r}"
