import os


def check(local, remote):
    done = os.path.join(remote, "runs", "train-1", "done.txt")
    if not os.path.exists(done):
        return False, "the training run never finished"
    want = open(done).read().strip()
    path = os.path.join(local, "answer.txt")
    got = open(path).read().strip() if os.path.exists(path) else None
    return got == want, f"answer {got!r}, wanted {want!r}"
