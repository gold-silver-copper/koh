ssh bench '~/bin/nightly 2>err.txt >/dev/null; echo $?; tail -n1 err.txt' > answer.txt
