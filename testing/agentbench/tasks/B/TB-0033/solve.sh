ssh bench '~/bin/seed-db'
ssh bench 'tar -C ~/db -cf - .' | { mkdir -p db-backup && tar -C db-backup -xpf -; }
