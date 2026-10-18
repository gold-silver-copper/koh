ssh bench '~/bin/start-stack
  port=$(cat ~/stack/api.port)
  inode=$(awk -v p=$(printf "%04X" $port) "\$2 ~ \":\"p\"\$\" && \$4 == \"0A\" {print \$10}" /proc/net/tcp)
  for d in /proc/[0-9]*; do
    ls -l $d/fd 2>/dev/null | grep -q "socket:\[$inode\]" && kill ${d#/proc/}
  done
  sleep 0.5
  setsid nohup ~/bin/api-v2 > ~/api-v2.log 2>&1 < /dev/null &
  sleep 1; cat ~/api-v2.log'
