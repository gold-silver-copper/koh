import os, re, subprocess


def crashes(text):
    cfg = dict((k.strip(), v.strip()) for k, v in (l.split("=", 1) for l in text.splitlines() if "=" in l))
    return cfg.get("simd") == "on" and float(cfg.get("contact_slop", 1)) < 0.005


def check(local, remote):
    repo = os.path.join(remote, "engine")
    if not os.path.isdir(os.path.join(repo, ".git")):
        return False, "~/engine was never created"
    git = lambda *a: subprocess.run(["git", "-C", repo, *a], capture_output=True, text=True,
                                    env=dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull)).stdout
    want = None
    for c in git("rev-list", "--reverse", "main").split():
        if crashes(git("show", f"{c}:src/solver.cfg")):
            want = c
            break
    path = os.path.join(local, "answer.txt")
    got = open(path).read().strip() if os.path.exists(path) else None
    return got == want and want is not None, f"answer {got!r}, wanted {want!r}"
