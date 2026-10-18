#!/usr/bin/env python3
"""Tables from bench.py's results, and grades from reviews if given.

    python3 -I report.py RESULTS.json [--grades GRADES.json] [--by cat]

Per configuration: runs, checker passes (with a 95% Wilson interval), grades (worked / hack /
failed, from GRADES.json: {"<config>/<task>/<repeat>": {"grade": ..., ...}}), and per run the
means of remote-tool calls, fux calls, Bash calls, seconds slept, polling loops, base64 uses and
wall time. With --by cat, the same per category.
"""
import argparse
import json
import math
from collections import defaultdict


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def key(r):
    return f"{r['config']}/{r['task']}/{r.get('repeat', 0)}"


def table(rows, grades):
    by = defaultdict(list)
    for r in rows:
        by[r["config"]].append(r)
    head = ("config", "runs", "pass", "95% CI", "worked", "hack", "failed", "tool", "fux", "bash",
            "sleep s", "loops", "b64", "wall s")
    out = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    for config, rs in sorted(by.items()):
        n = len(rs)
        k = sum(r["ok"] for r in rs)
        lo, hi = wilson(k, n)
        g = defaultdict(int)
        for r in rs:
            g[grades.get(key(r), {}).get("grade", "?")] += 1
        mean = lambda f: sum(r.get(f) or 0 for r in rs) / n
        out.append("| " + " | ".join([
            config, str(n), f"{k}", f"{lo:.0%}–{hi:.0%}",
            str(g["worked"]), str(g["hack"]), str(g["failed"]),
            f"{mean('tool_calls'):.1f}", f"{mean('fux_calls'):.1f}", f"{mean('bash_calls'):.1f}",
            f"{mean('sleep_s'):.1f}", f"{mean('polling_loops'):.2f}", f"{mean('base64'):.2f}",
            f"{mean('seconds'):.0f}"]) + " |")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("results", nargs="+")
    ap.add_argument("--grades")
    ap.add_argument("--by")
    args = ap.parse_args()
    rows = [r for path in args.results for r in json.load(open(path)) if not r.get("harness_error")]
    grades = json.load(open(args.grades)) if args.grades else {}
    print(table(rows, grades))
    if args.by:
        groups = defaultdict(list)
        for r in rows:
            groups[r.get(args.by, "")].append(r)
        for name, rs in sorted(groups.items()):
            print(f"\n### {args.by} = {name}\n")
            print(table(rs, grades))
    errors = sum(1 for path in args.results for r in json.load(open(path)) if r.get("harness_error"))
    if errors:
        print(f"\n{errors} runs ended in a harness error and are left out.")


if __name__ == "__main__":
    main()
