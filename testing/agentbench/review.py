#!/usr/bin/env python3
"""Batches of runs for graders to judge, and their grades gathered into one file.

    python3 -I review.py batches RESULTS.json --out DIR [--size 15]
    python3 -I review.py gather DIR --out GRADES.json

`batches` writes DIR/batch-NNN.md: per run, the task's goal, the checker's verdict, every tool
call the agent made (in full, from its stream), and its final message. A grader reads one batch
and writes DIR/batch-NNN.json: {"<config>/<task>/<repeat>": {"grade": "worked"|"hack"|"failed",
"why": "...", "friction": ["..."]}} by the grade definitions in README.md. `gather` merges them.
"""
import argparse
import glob
import json
import os

GUIDE = """Grade each run by README.md's definitions:
- worked: the checker passed, done plainly: waits on conditions, not on time; reads what it needs
  directly; no blind retries; no encoding tricks to move data.
- hack: the checker passed, but through a workaround: guessed sleeps or polling loops, scraping a
  screen for what the tool should report, base64 or here-doc tricks to move a file, sentinel lines
  to learn an exit status, raw escape sequences, a retry because a result could not be trusted.
- failed: the checker failed, or the agent gave up or ran out of time.
A checker pass is required for worked or hack; a checker failure is always failed. Judge from the
tool calls, not from what the agent says about itself. For each run also list the friction points
the transcript shows (what got in the way, in a few words each), whatever the grade.
"""


def calls(stream_path):
    out = []
    for line in open(stream_path, errors="replace"):
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        item = msg.get("item") or {}
        if msg.get("type") == "item.completed" and item.get("type") == "command_execution":
            out.append(("call", item.get("command") or ""))
            out.append(("result", f"[exit {item.get('exit_code')}] " + (item.get("aggregated_output") or "")))
        if msg.get("type") == "assistant":
            for part in msg.get("message", {}).get("content", []):
                if part.get("type") == "tool_use":
                    inp = part.get("input", {})
                    out.append(("call", inp.get("command") or json.dumps(inp)))
        if msg.get("type") == "user":
            for part in msg.get("message", {}).get("content", []) if isinstance(msg.get("message", {}).get("content"), list) else []:
                if part.get("type") == "tool_result":
                    content = part.get("content")
                    text = content if isinstance(content, str) else " ".join(
                        c.get("text", "") for c in content or [] if isinstance(c, dict))
                    out.append(("result", text))
    return out


def batches(results, out_dir, size):
    os.makedirs(out_dir, exist_ok=True)
    rows = [r for r in json.load(open(results)) if not r.get("harness_error")]
    for n in range(0, len(rows), size):
        parts = [f"# Batch {n // size + 1:03d}\n\n{GUIDE}\nWrite your grades to `batch-{n // size + 1:03d}.json` beside this file.\n"]
        for r in rows[n:n + size]:
            key = f"{r['config']}/{r['task']}/{r.get('repeat', 0)}"
            prompt = open(os.path.join(r["root"], "state", "prompt.md")).read()
            goal = prompt.split("Your task:", 1)[-1].split("Rules:", 1)[0].strip()
            parts.append(f"\n---\n\n## {key}\n\n**Tool:** {r['config']}  **Checker:** {'pass' if r['ok'] else 'FAIL'} ({r['why']})  "
                         f"**Timed out:** {r.get('timed_out')}  **Seconds:** {r.get('seconds')}\n\n**Goal:**\n\n{goal}\n\n**Transcript:**\n")
            for kind, text in calls(os.path.join(r["root"], "state", "stream.jsonl")):
                limit = 4000 if kind == "call" else 1000
                text = text if len(text) < limit else text[:limit // 2] + f"\n… [{len(text) - limit} bytes cut] …\n" + text[-limit // 2:]
                parts.append(f"\n{'$' if kind == 'call' else '>'} " + text.replace("\n", "\n  ") + "\n")
            parts.append(f"\n**Final message:**\n\n{(r.get('final') or '')[-1500:]}\n")
        with open(os.path.join(out_dir, f"batch-{n // size + 1:03d}.md"), "w") as f:
            f.write("".join(parts))
    print(f"{(len(rows) + size - 1) // size} batches in {out_dir}")


def gather(out_dir, out):
    grades = {}
    for path in sorted(glob.glob(os.path.join(out_dir, "batch-*.json"))):
        grades.update(json.load(open(path)))
    with open(out, "w") as f:
        json.dump(grades, f, indent=1)
    counts = {}
    for g in grades.values():
        counts[g.get("grade")] = counts.get(g.get("grade"), 0) + 1
    print(f"{len(grades)} grades: {counts}")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("batches")
    b.add_argument("results")
    b.add_argument("--out", required=True)
    b.add_argument("--size", type=int, default=15)
    g = sub.add_parser("gather")
    g.add_argument("dir")
    g.add_argument("--out", required=True)
    args = ap.parse_args()
    if args.cmd == "batches":
        batches(args.results, args.out, args.size)
    else:
        gather(args.dir, args.out)


if __name__ == "__main__":
    main()
