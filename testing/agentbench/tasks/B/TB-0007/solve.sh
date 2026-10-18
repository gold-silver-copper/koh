ssh bench '~/bin/run-tests' | sed -n 's/^test \(.*\) \.\.\. FAILED$/\1/p' > answer.txt
