ssh bench '~/bin/farm --daemon'
ssh bench 'pids=$(~/bin/farm --status | sed -n "s/^  worker [0-9]*: pid \([0-9]*\) up$/\1/p")
~/bin/farm --stop; while [ -e ~/farm/farm.pid ]; do sleep 0.5; done
for p in $pids; do kill -0 $p 2>/dev/null && kill -9 $p; done; true'
