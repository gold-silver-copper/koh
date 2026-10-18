ssh bench '~/bin/reindex --start'
ssh bench 'until ~/bin/reindex --status | grep -q ^finished; do sleep 1; done; ~/bin/reindex --verify' >&2
ssh bench '~/bin/reindex --status' | sed -n 's/^finished: indexed \([0-9]*\) documents$/\1/p' > answer.txt
