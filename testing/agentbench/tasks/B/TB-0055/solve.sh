ssh bench 'nohup ~/bin/syncd > syncd.out 2>&1 < /dev/null &'
ssh bench 'until grep -q "^batch 3 synced" syncd.out; do sleep 0.5; done; p=$(cat ~/sync/syncd.pid); kill -USR1 $p; while kill -0 $p 2>/dev/null; do sleep 0.2; done'
