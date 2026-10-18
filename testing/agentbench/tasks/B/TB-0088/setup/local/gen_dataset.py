#!/usr/bin/env python3
"""Writes dataset.bin (32 MiB of training samples) in the current directory."""
import random, struct

with open("dataset.bin", "wb") as f:
    f.write(b"DSET" + struct.pack("<I", 32))
    for shard in range(32):
        f.write(random.Random(880 + shard).randbytes(1 << 20))
print("wrote dataset.bin")
