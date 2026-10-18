#!/usr/bin/env python3
"""Reads a metrics stream on stdin, checks it, and writes summary.json beside this script."""
import hashlib, json, os, struct, sys

data = sys.stdin.buffer.read()
out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "summary.json")


def finish(**kw):
    json.dump(kw, open(out, "w"), indent=1)
    print(json.dumps(kw))
    sys.exit(0 if kw.get("valid") else 1)


if len(data) < 44 or data[:4] != b"MTRC":
    finish(valid=False, reason=f"not a metrics stream ({len(data)} bytes)")
n = struct.unpack("<Q", data[4:12])[0]
payload, trailer = data[12:-32], data[-32:]
if len(payload) != 12 * n:
    finish(valid=False, reason=f"{len(payload)} payload bytes, header promises {12 * n}")
digest = hashlib.sha256(payload).digest()
if digest != trailer:
    finish(valid=False, reason="checksum mismatch: the stream was altered in transit")
total = sum(v for _, _, v in struct.iter_unpack("<III", payload))
finish(valid=True, records=n, value_sum=total, sha256=digest.hex())
