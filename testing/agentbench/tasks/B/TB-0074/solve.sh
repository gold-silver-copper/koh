# grep -m1 exits at the line; stress-sim then dies of SIGPIPE on its next write
ssh bench '~/bin/stress-sim | grep -m1 THRESHOLD' | sed 's/.*iteration \([0-9]*\).*/\1/' > answer.txt
ssh bench 'kill $(cat ~/.bench/stress.pid) 2>/dev/null; true'
