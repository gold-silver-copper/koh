#!/usr/bin/env python3
"""Reads events (JSON lines) on stdin; writes them with personal data removed."""
import hashlib, json, sys

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    ev = json.loads(line)
    ev["player"] = "p-" + hashlib.sha256(ev.pop("player").encode()).hexdigest()[:10]
    ev.pop("email", None)
    ev["ip"] = ".".join(ev["ip"].split(".")[:2] + ["0", "0"])
    sys.stdout.write(json.dumps(ev, sort_keys=True) + "\n")
