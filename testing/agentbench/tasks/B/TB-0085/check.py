import hashlib, json, os, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))


def check(local, remote):
    raw = subprocess.run([sys.executable, os.path.join(HERE, "setup", "remote", "bin", "emit-events")],
                         capture_output=True, check=True).stdout
    red = subprocess.run([sys.executable, os.path.join(HERE, "setup", "local", "redact.py")], input=raw,
                         capture_output=True, check=True).stdout
    want = hashlib.sha256(red).hexdigest()
    for d, _, files in os.walk(remote):
        for f in files:
            p = os.path.join(d, f)
            try:
                if os.path.getsize(p) < 50_000_000 and b"@example.invalid" in open(p, "rb").read():
                    if os.path.join(remote, "bin") not in p:
                        return False, f"unredacted events were written on the remote: {p}"
            except OSError:
                pass
    rec = os.path.join(remote, ".bench", "load.json")
    if not os.path.exists(rec):
        return False, "load-events never ran"
    last = json.loads(open(rec).read().splitlines()[-1])
    return last["sha256"] == want, f"load-events last got {last['events']} events, " + ("the redacted output" if last["sha256"] == want else "not the redacted output")
