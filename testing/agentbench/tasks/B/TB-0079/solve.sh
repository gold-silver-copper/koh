ssh bench '~/bin/import-scene ~/levels/level3.json > /dev/null 2> err.txt; s=$?; tail -1 err.txt; echo $s' > answer.txt
