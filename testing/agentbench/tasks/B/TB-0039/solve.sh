printf 'load team-annual\ndiscount EDU\nquote 37\nquit\n' | ssh bench '~/bin/pricer' | sed -n 's/^total: \(.*\) USD$/\1/p' > answer.txt
