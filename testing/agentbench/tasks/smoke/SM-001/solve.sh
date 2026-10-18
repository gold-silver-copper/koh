ssh bench 'grep -o "[0-9]* warnings" status.txt' | cut -d' ' -f1 > answer.txt
