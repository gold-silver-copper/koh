import os, re, shutil, subprocess

HERE = os.path.dirname(os.path.abspath(__file__))


def check(local, remote):
    crate = os.path.join(remote, "crates", "ringbuf")
    ref = os.path.join(HERE, "setup", "remote", "crates", "ringbuf")
    for f in ("tests/ring.rs", "Cargo.toml"):
        if open(os.path.join(crate, f), "rb").read() != open(os.path.join(ref, f), "rb").read():
            return False, f"{f} was changed"
    if open(os.path.join(crate, "src", "lib.rs"), "rb").read() == open(os.path.join(ref, "src", "lib.rs"), "rb").read():
        return False, "src/lib.rs is unchanged; the bug is still there"
    work = os.path.join(remote, ".bench", "check-crate")
    shutil.rmtree(work, ignore_errors=True)
    shutil.copytree(crate, work, ignore=shutil.ignore_patterns("target"))
    env = dict(os.environ, CARGO_TARGET_DIR=os.path.join(remote, ".bench", "check-target"), CARGO_BUILD_JOBS="2")
    try:
        p = subprocess.run(["cargo", "test", "--offline", "-j", "2", "--test", "ring"], cwd=work, env=env,
                           capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return False, "cargo test timed out"
    m = re.search(r"test result: (\w+)\. (\d+) passed; (\d+) failed", p.stdout)
    if p.returncode != 0 or not m or m.group(2) != "4":
        return False, f"cargo test fails: {(p.stdout + p.stderr)[-400:]}"
    return True, "all 4 tests pass with the tests unchanged"
