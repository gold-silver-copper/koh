ssh bench '~/bin/build-engine' | grep -A1 '^error\[' | sed -n 's/^ *--> \(.*\):[0-9]*$/\1/p' > answer.txt
