import os


def check(local, remote):
    want = open(os.path.join(local, "note.txt"), "rb").read()
    inbox = os.path.join(remote, "notes", "inbox")
    notes = sorted(os.listdir(inbox)) if os.path.isdir(inbox) else []
    if not notes:
        return False, "no note was filed"
    good = [n for n in notes if open(os.path.join(inbox, n), "rb").read() == want]
    if len(notes) != 1:
        return False, f"{len(notes)} notes were filed ({len(good)} identical to note.txt); wanted exactly one"
    if not good:
        got = open(os.path.join(inbox, notes[0]), "rb").read()
        return False, f"the filed note differs from note.txt ({len(got)} bytes, wanted {len(want)})"
    return True, "the note was filed intact, once"
