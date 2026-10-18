import hashlib, os


def check(local, remote):
    scene = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "setup", "remote", "scenes",
                              "forest night", "scene.json"), "rb").read()
    want = hashlib.sha256(scene + b"#1042").hexdigest()[:16]
    path = os.path.join(local, "answer.txt")
    got = open(path).read().strip() if os.path.exists(path) else None
    return got == want, f"answer {got!r}, wanted {want!r}"
