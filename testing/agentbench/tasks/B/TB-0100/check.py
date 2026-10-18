import os, re, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))


def check(local, remote):
    r = os.path.join(HERE, "setup", "remote")
    out = subprocess.run([sys.executable, os.path.join(r, "bin", "tdb"), os.path.join(r, "vm", "solver.prog")],
                         input="break 33\nrun\nc\nc\nc\nc\nprint r3\nquit\n", capture_output=True, text=True).stdout
    want = re.findall(r"r3 = (-?\d+)", out)[-1]
    path = os.path.join(local, "answer.txt")
    got = open(path).read().strip() if os.path.exists(path) else None
    return got == want, f"answer {got!r}, wanted {want!r}"
