# a foreground stage, killed by the drop, leaves a stale lock behind
ssh bench '~/bin/deploy stage'
sleep 1
ssh bench '~/bin/deploy unlock && nohup ~/bin/deploy stage > stage.log 2>&1 < /dev/null &'
until ssh bench 'grep -q "^staged 2.4.0" stage.log'; do sleep 1; done
ssh bench '~/bin/deploy commit'
