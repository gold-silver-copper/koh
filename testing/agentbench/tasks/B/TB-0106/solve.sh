ssh bench 'setsid nohup ~/bin/export-world > export.log 2>&1 < /dev/null &'
until ssh bench 'while [ ! -e ~/.bench/export-done.json ]; do sleep 0.5; done'; do sleep 1; done
ssh bench 'cat ~/out/world.sum' > answer.txt
