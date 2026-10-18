p=$(ssh bench '~/bin/export-snapshot' | sed -n 's/^snapshot: //p')
scp -q "bench:$p" snapshot.bin
