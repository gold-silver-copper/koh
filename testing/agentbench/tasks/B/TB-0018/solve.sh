ssh bench '~/bin/rebuild-catalog' | sed -n 's/^rebuild complete: digest=//p' > digest.txt
