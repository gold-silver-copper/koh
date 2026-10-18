import os

WANT = ['assets/css/home/0062-8495.css', 'assets/docs/home/0597-1503.pdf', 'assets/img/app/0481-2132.png',
        'assets/js/blog/1868-4297.js', 'assets/js/help/0179-1548.js', 'assets/js/shop/0908-6793.js',
        'assets/video/home/2363-9976.mp4']


def check(local, remote):
    path = os.path.join(local, "failed.txt")
    if not os.path.exists(path):
        return False, "no failed.txt"
    raw = open(path, encoding="utf-8", errors="replace").read()
    if "\x1b" in raw:
        return False, "failed.txt contains terminal escape sequences"
    got = [l.strip() for l in raw.splitlines() if l.strip()]
    if len(got) != len(set(got)):
        return False, f"duplicate lines in failed.txt: {got!r}"
    missing, extra = sorted(set(WANT) - set(got)), sorted(set(got) - set(WANT))
    if missing or extra:
        return False, f"missing {missing!r}, extra {extra!r}"
    return True, "all 7 failed files listed"
