import hashlib, json, os

WANT = {"listen": "127.0.0.1:7400", "workers": "12", "log_level": "debug", "cache_mb": "512",
        "tick_rate": "60", "max_sessions": "2000"}


def check(local, remote):
    conf = os.path.join(remote, "srv", "app.conf")
    text = open(conf).read()
    lines = text.splitlines(True)
    if not lines or not lines[0].startswith("# managed by visconf; checksum: "):
        return False, "~/srv/app.conf lost its visconf header"
    body = "".join(lines[1:])
    if lines[0].split(": ")[1].strip() != hashlib.sha256(body.encode()).hexdigest()[:16]:
        return False, "~/srv/app.conf was changed without visconf (its checksum does not match)"
    rec = os.path.join(remote, ".bench", "visconf.json")
    if not os.path.exists(rec):
        return False, "visconf never installed a change"
    if json.loads(open(rec).read().splitlines()[-1])["sha256"] != hashlib.sha256(text.encode()).hexdigest():
        return False, "~/srv/app.conf is not what visconf last installed"
    got = {}
    for l in body.splitlines():
        if "=" in l and not l.strip().startswith("#"):
            k, v = (x.strip() for x in l.split("=", 1))
            got[k] = v
    return got == WANT, f"settings {got}, wanted {WANT}"
