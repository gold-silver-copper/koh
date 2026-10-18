ssh bench 'nohup ~/bin/devserver > dev.log 2>&1 < /dev/null &'
ssh bench 'until grep -q "^ready: ticket=" dev.log; do sleep 0.5; done; ~/bin/smoke "$(sed -n "s/^ready: ticket=//p" dev.log)"'
