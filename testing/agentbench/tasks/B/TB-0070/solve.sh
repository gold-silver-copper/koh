ssh bench '~/bin/render-farm' | tr '\r' '\n' | sed 's/\x1b\[[0-9;]*m//g' | python3 -c '
import re, sys
failed, ok = set(), set()
for line in sys.stdin:
    m = re.match(r"\[w\d\] frame (\d+) (ok|FAILED)", line)
    if m:
        (ok if m.group(2) == "ok" else failed).add(int(m.group(1)))
print("\n".join(str(n) for n in sorted(failed - ok)))
' > answer.txt
