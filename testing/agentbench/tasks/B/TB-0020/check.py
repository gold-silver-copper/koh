import os


def check(local, remote):
    rec = os.path.join(remote, ".render", "last")
    if not os.path.exists(rec):
        return False, "render-frames was never run"
    want = open(rec).read().strip()
    path = os.path.join(local, "answer.txt")
    if not os.path.exists(path):
        return False, "no answer.txt"
    lines = open(path).read().split()
    if len(lines) != 2:
        return False, f"answer.txt should have two lines, has {lines!r}"
    if lines[0] != "142":
        return False, f"exit status {lines[0]!r}, wanted '142' (killed by SIGALRM)"
    if lines[1] != want:
        return False, f"last frame {lines[1]!r}, wanted {want!r}"
    return True, "exit status and last frame are right"
