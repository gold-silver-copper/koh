import os


def want():
    total = 0.0
    for s in range(1, 38):
        total += 119.0 if s <= 10 else 119.0 * (0.85 if s <= 50 else 0.80)
    return f"{round(total * 0.7, 2):,.2f}"


def check(local, remote):
    hist = os.path.join(remote, ".pricer", "history")
    if not os.path.exists(hist) or "quote" not in open(hist).read():
        return False, "pricer was never asked for a quote"
    path = os.path.join(local, "answer.txt")
    got = open(path).read().strip() if os.path.exists(path) else None
    got = got.replace(" USD", "") if got else got
    return got == want(), f"answer {got!r}, wanted {want()!r}"
