ssh bench '~/bin/tally' < orders.csv | sed -n 's/^total: //p' > answer.txt
