ssh bench 'nohup ~/bin/warm-cache > warm.out 2>&1 < /dev/null &'
ssh bench 'sleep 3; sed -i "s/^max_entries = .*/max_entries = 50000/" ~/cache/limits.conf'
ssh bench 'until grep -q "^warmed" warm.out; do sleep 1; done; sed -n "s/^warmed \([0-9]*\) entries/\1/p" warm.out' > answer.txt
