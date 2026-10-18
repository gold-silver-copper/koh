pids=$(ssh bench '~/bin/start-workers' | grep -o 'pid [0-9]*' | cut -d' ' -f2 | tr '\n' ,)
ssh bench "sleep 4; ps -o pid=,rss= -p ${pids%,} | sort -k2 -n | tail -1 | awk '{print \$1}' | xargs kill"
