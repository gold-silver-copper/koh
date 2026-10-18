import json
import os


def check(local, remote):
    path = os.path.join(remote, "apps", "ledger", "ledger.conf")
    if not os.path.exists(path):
        return False, "no ~/apps/ledger/ledger.conf (the install did not finish there)"
    conf = json.load(open(path))
    want = {"install_dir": os.path.join(remote, "apps", "ledger"), "telemetry": False, "port": 9091,
            "database": "sqlite", "license": "accepted"}
    if os.path.normpath(conf.get("install_dir", "")) != want["install_dir"]:
        return False, f"installed into {conf.get('install_dir')!r}"
    conf["install_dir"] = want["install_dir"]
    return conf == want, f"ledger.conf is {conf}, wanted {want}"
