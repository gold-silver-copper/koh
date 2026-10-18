ssh bench 'setsid nohup ~/bin/render-pool > pool.log 2>&1 < /dev/null &
  until grep -q "pool ready" pool.log; do sleep 0.2; done
  kill -STOP $(grep render-pool ~/.bench/pool.pids | cut -d" " -f1)
  kill -KILL $(cut -d" " -f1 ~/.bench/pool.pids) 2>/dev/null; true'
