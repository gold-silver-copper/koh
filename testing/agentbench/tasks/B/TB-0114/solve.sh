ssh bench '~/bin/start-workers; sleep 3; ps -o pid=,pcpu=,args= -u "$(id -u)" | grep "$HOME/bin/[w]orker --shard" | sort -k2 -rn | head -1 | awk "{print \$1}" | xargs kill'
