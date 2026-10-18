ssh bench '~/bin/nightly-dump'
ssh bench 'while [ ! -e ~/dumps/nightly.sql.gz ]; do sleep 0.5; done; sha256sum ~/dumps/nightly.sql.gz' | cut -d' ' -f1 > answer.txt
