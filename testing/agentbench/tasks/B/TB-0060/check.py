import json
import os


def check(local, remote):
    d = os.path.join(remote, "svc")
    if not os.path.exists(os.path.join(d, ".running.json")):
        return False, "the service never started"
    conf = json.load(open(os.path.join(d, ".running.json")))
    try:
        st = open(f"/proc/{conf['pid']}/stat").read().rsplit(")", 1)[1].split()[0]
        up = st != "Z"
    except OSError:
        up = False
    if not up:
        return False, "the service is not running any more"
    if conf["port"] != 8080:
        return False, f"the service listens on port {conf['port']}, wanted 8080"
    if os.path.realpath(conf["data_dir"]) != os.path.realpath(os.path.join(d, "var")):
        return False, f"the service's data is in {conf['data_dir']}, wanted ~/svc/var"
    ping = os.path.join(d, ".ping-ok")
    if not os.path.exists(ping) or json.load(open(ping))["pid"] != conf["pid"]:
        return False, "svc-ping never succeeded against the running service"
    return True, "the service is up on 8080 with its data in ~/svc/var, and svc-ping succeeded"
