import os
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))


def check(local, remote):
    crate = os.path.join(remote, "crates", "ringbuf")
    orig = open(os.path.join(HERE, "setup/remote/crates/ringbuf/tests/ring.rs")).read()
    test = os.path.join(crate, "tests", "ring.rs")
    if not os.path.exists(test) or open(test).read() != orig:
        return False, "tests/ring.rs was changed"
    path = os.path.join(local, "answer.txt")
    got = open(path).read().strip() if os.path.exists(path) else None
    if got != "iter_after_wrap_is_oldest_first":
        return False, f"answer {got!r}, wanted 'iter_after_wrap_is_oldest_first'"
    env = dict(os.environ, CARGO_BUILD_JOBS="2", CARGO_TARGET_DIR=os.path.join(crate, "target", "check"))
    try:
        p = subprocess.run(["cargo", "test", "--offline", "-q", "-j", "2"], cwd=crate, env=env,
                           capture_output=True, text=True, timeout=240)
    except subprocess.TimeoutExpired:
        return False, "cargo test took more than 4 minutes"
    if p.returncode != 0:
        return False, "cargo test still fails: " + (p.stdout + p.stderr)[-400:]
    if "7 passed" not in p.stdout:
        return False, "cargo test passes, but not with the 7 tests of tests/ring.rs: " + p.stdout[-300:]
    return True, "the bug is fixed and all 7 tests pass"
