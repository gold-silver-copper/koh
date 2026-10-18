# run in the foreground, as a naive client would: the drop kills it, then resume detached
ssh bench '~/bin/migrate-shards'
sleep 1
ssh bench 'nohup ~/bin/migrate-shards --resume > migrate.log 2>&1 < /dev/null &'
until ssh bench 'grep -q "\"finished\": true" ~/migrate/checkpoint.json'; do sleep 1; done
