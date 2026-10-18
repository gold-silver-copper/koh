import os
import sqlite3


def check(local, remote):
    path = os.path.join(remote, "inventory.db")
    if not os.path.exists(path):
        return False, "invsh was never started (no ~/inventory.db)"
    db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    rows = db.execute("""select s.sku, i.reorder_level - s.qty from stock s join items i on i.sku = s.sku
                         join warehouses w on w.id = s.warehouse_id
                         where w.code = 'east' and s.qty < i.reorder_level order by 2 desc""").fetchall()
    want = [str(len(rows)), rows[0][0]]
    if rows[0][1] == rows[1][1]:
        return False, "fixture problem: a tie for the largest shortfall"
    ans = os.path.join(local, "answer.txt")
    got = open(ans).read().split() if os.path.exists(ans) else None
    return got == want, f"answer {got!r}, wanted {want!r}"
