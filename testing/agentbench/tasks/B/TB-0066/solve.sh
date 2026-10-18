ssh bench '~/bin/selftest' | sed 's/\x1b\[[0-9;]*m//g' | sed -n 's/^\[ FAIL \] //p' | sort > answer.txt
