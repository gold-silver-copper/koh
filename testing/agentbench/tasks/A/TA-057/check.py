import os
import json


def read(path):
    try:
        with open(path, errors="replace") as f:
            return f.read()
    except OSError:
        return None


def readb(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError:
        return None


def alive(pid):
    try:
        with open(f"/proc/{int(pid)}/stat") as f:
            return f.read().rsplit(")", 1)[1].split()[0] not in ("Z", "X")
    except (OSError, ValueError, IndexError):
        return False


def fixture(name, side="remote/bin"):
    """The task's own copy of a fixture, loaded as a module (its main guarded)."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "setup", *side.split("/"), name)
    ns = {"__name__": "fixture", "__file__": path}
    with open(path) as f:
        exec(compile(f.read(), path, "exec"), ns)
    return ns


import subprocess
TEST = 'use textstats::*;\n\n#[test]\nfn counts_lines() {\n    assert_eq!(line_count("a\\nb\\nc"), 3);\n}\n\n#[test]\nfn trailing_newline_is_not_a_line() {\n    assert_eq!(line_count("a\\nb\\n"), 2);\n    assert_eq!(line_count(""), 0);\n}\n\n#[test]\nfn counts_words() {\n    assert_eq!(word_count("  the quick\\tbrown\\n fox "), 4);\n}\n\n#[test]\nfn longest_line_first_on_tie() {\n    assert_eq!(longest_line("ab\\ncd\\nx"), Some("ab"));\n    assert_eq!(longest_line(""), None);\n}\n\n#[test]\nfn frequencies() {\n    assert_eq!(char_freq("abca b"), vec![(\'a\', 2), (\'b\', 2), (\'c\', 1)]);\n}\n'
def check(local, remote):
    crate = os.path.join(remote, "crates", "textstats")
    if read(os.path.join(crate, "tests", "stats.rs")) != TEST:
        return False, "the tests were changed"
    env = dict(os.environ, CARGO_TARGET_DIR=os.path.join(crate, "target"), CARGO_BUILD_JOBS="2")
    r = subprocess.run(["cargo", "test", "--offline", "-q"], cwd=crate, env=env, capture_output=True,
                       text=True, timeout=600)
    if r.returncode != 0:
        return False, "cargo test fails: " + (r.stdout + r.stderr)[-400:]
    return True, "cargo test passes"
