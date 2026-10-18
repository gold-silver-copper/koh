#!/usr/bin/env python3
"""Writes capture.bin (a 24 MiB profiler capture) in the current directory."""
import hashlib, random, struct

body = b"".join(random.Random(1090 + i).randbytes(1 << 20) for i in range(24))
with open("capture.bin", "wb") as f:
    f.write(b"CAPT" + struct.pack("<Q", len(body)) + hashlib.sha256(body).digest() + body)
print("wrote capture.bin")
