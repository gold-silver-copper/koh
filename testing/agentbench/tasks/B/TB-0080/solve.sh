ssh bench '~/bin/pack-textures > /dev/null 2> err.txt; s=$?; echo SIG$(kill -l $s); tail -1 err.txt | sed "s/packing atlas \([0-9]*\).*/\1/"' > answer.txt
