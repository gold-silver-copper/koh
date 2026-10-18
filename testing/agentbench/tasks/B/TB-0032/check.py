import os
import stat

HERE = os.path.dirname(os.path.abspath(__file__))


def check(local, remote):
    old = open(os.path.join(HERE, "setup/remote/.deployd/authorized_keys")).read().splitlines()
    new = open(os.path.join(HERE, "setup/local/deploy_key.pub")).read().strip()
    ak = os.path.join(remote, ".deployd", "authorized_keys")
    if not os.path.exists(ak):
        return False, "~/.deployd/authorized_keys is gone"
    lines = [l for l in open(ak).read().splitlines() if l.strip()]
    if lines != old + [new]:
        return False, f"authorized_keys has {len(lines)} lines {[l[-24:] for l in lines]}, wanted the 3 old keys then the deploy key"
    dmode = stat.S_IMODE(os.stat(os.path.join(remote, ".deployd")).st_mode)
    fmode = stat.S_IMODE(os.stat(ak).st_mode)
    if dmode != 0o700 or fmode != 0o600:
        return False, f"modes are ~/.deployd {dmode:o} and authorized_keys {fmode:o}, wanted 700 and 600"
    return True, "the key is installed with the right modes"
