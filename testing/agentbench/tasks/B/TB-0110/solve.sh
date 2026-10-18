ssh bench 'setsid nohup ~/bin/asset-server > ~/asset-server.log 2>&1 < /dev/null &
  while [ ! -e ~/asset-server.port ]; do sleep 0.2; done; cat ~/asset-server.port; echo; sleep 5'
until ssh bench 'cat ~/asset-server.port' > answer.txt; do sleep 1; done
