import os
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))


def check(local, remote):
    out = subprocess.run(["python3", "-I", os.path.join(HERE, "setup/remote/bin/audit-perms")],
                         capture_output=True, text=True, check=True).stdout.splitlines()
    want = sum(1 for l in out[1:-1] if l.split()[1] == "nobody" and l[8] == "w")
    path = os.path.join(local, "answer.txt")
    got = open(path).read().strip() if os.path.exists(path) else None
    return got == str(want), f"answer {got!r}, wanted {str(want)!r}"
