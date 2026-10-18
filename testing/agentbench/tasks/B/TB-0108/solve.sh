ssh bench 'rm -f ~/mig.in; mkfifo ~/mig.in
  setsid nohup sleep 300 > ~/mig.in 2>/dev/null < /dev/null &
  echo $! > ~/mig.holder
  setsid nohup ~/bin/migrate-db < ~/mig.in > ~/mig.log 2>&1 &
  tail -f ~/mig.log'
until ssh bench 'until grep -q "Delete them" ~/mig.log; do sleep 0.5; done'; do sleep 1; done
ssh bench 'echo y > ~/mig.in'
until ssh bench 'until grep -q "migration complete\|aborted" ~/mig.log; do sleep 0.5; done'; do sleep 1; done
ssh bench 'kill $(cat ~/mig.holder)'
