ssh bench '~/bin/describe-node' | tr ' ' '\n' | sed -n 's/^shard_owner=//p' > answer.txt
