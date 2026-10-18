ssh bench '~/bin/export-assets' | sed -n 's/^exported \([0-9]*\) assets.*/\1/p' > answer.txt
