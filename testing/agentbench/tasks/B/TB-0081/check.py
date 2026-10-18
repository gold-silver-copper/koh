import os


def check(local, remote):
    if not os.path.exists(os.path.join(remote, ".bench", "sim.ran")):
        return False, "physics-sim never ran to its crash"
    path = os.path.join(local, "answer.txt")
    got = open(path).read().strip() if os.path.exists(path) else None
    return got == "solve_contacts_simd", f"answer {got!r}, wanted 'solve_contacts_simd'"
