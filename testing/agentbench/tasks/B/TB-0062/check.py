import os

WANT = "active toolchain: nightly-2026-09-30-aarch64 (override from ~/game/rust-toolchain.toml)"


def check(local, remote):
    path = os.path.join(local, "answer.txt")
    if not os.path.exists(path):
        return False, "no answer.txt"
    got = open(path).read().strip("\n")
    return got.strip() == WANT, f"answer {got!r}, wanted {WANT!r}"
