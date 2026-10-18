import json, os

HERE = os.path.dirname(os.path.abspath(__file__))


def same(a, b):
    return os.path.exists(a) and open(a, "rb").read() == open(b, "rb").read()


def check(local, remote):
    ref = os.path.join(HERE, "setup", "remote")
    for f in ("sdk/2.6/VERSION", "sdk/2.6/settings.toml", "sdk/2.6/bin/sdkc"):
        if not same(os.path.join(remote, f), os.path.join(ref, f)):
            return False, f"~/{f} was changed or removed"
    if not same(os.path.join(remote, ".sdkrc"), os.path.join(ref, ".sdkrc")):
        return False, "the default SDK changed (~/.sdkrc)"
    m = os.path.join(remote, "sdk", "2.7.0", "manifest.json")
    if not os.path.exists(m):
        return False, "no SDK installed in ~/sdk/2.7.0"
    if os.path.exists(os.path.join(remote, "sdk", "2.7")):
        return False, "an SDK was also installed in ~/sdk/2.7"
    got = json.load(open(m))
    want = {"version": "2.7.0", "components": ["compiler", "debugger"], "settings_imported": True}
    if got != want:
        return False, f"installed {got}, wanted {want}"
    if not same(os.path.join(remote, "sdk", "2.7.0", "settings.toml"), os.path.join(ref, "sdk", "2.6", "settings.toml")):
        return False, "settings were not imported"
    return True, "SDK 2.7.0 installed as asked"
