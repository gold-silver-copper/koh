import os
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))


def check(local, remote):
    path = os.path.join(local, "prod.conf")
    if not os.path.exists(path):
        return False, "no prod.conf in the local directory"
    want = subprocess.run(["python3", "-I", os.path.join(HERE, "setup/remote/bin/render-config")],
                          cwd=os.path.join(HERE, "setup/remote/proj"), env={"STAGE": "prod", "PATH": "/usr/bin:/bin"},
                          capture_output=True, check=True).stdout
    got = open(path, "rb").read()
    if got == want:
        return True, "prod.conf matches the rendered prod config"
    if b"warning" in got:
        return False, "prod.conf contains the stderr warnings"
    if b"config for dev" in got:
        return False, "prod.conf is the dev config"
    return False, f"prod.conf differs from the rendered config ({len(got)} bytes, wanted {len(want)})"
