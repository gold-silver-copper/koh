import os
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))


def check(local, remote):
    err = subprocess.run(["python3", "-I", os.path.join(HERE, "setup/remote/bin/lint-legacy")],
                         capture_output=True, text=True, check=True).stderr.splitlines()
    want = sum(1 for l in err if l.startswith("warning[deprecated]:"))
    path = os.path.join(local, "answer.txt")
    got = open(path).read().strip() if os.path.exists(path) else None
    return got == str(want), f"answer {got!r}, wanted {str(want)!r}"
