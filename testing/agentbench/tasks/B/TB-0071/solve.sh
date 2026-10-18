ssh bench '~/bin/dump-journal' | grep -o 'Out of memory: Killed process [0-9]* ([^)]*)' > kills.txt
wc -l < kills.txt | tr -d ' ' > answer.txt
sed 's/.*(\(.*\))/\1/' kills.txt | sort | uniq -c | sort -rn | head -1 | awk '{print $2}' >> answer.txt
rm kills.txt
