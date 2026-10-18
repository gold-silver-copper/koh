ssh bench '~/bin/invsh' > out.txt <<'IN'
find category=potions rarity=epic
find category=potions rarity=legendary
quit
IN
grep -o '[0-9]* matches' out.txt | awk '{s += $1} END {print s}' > answer.txt
rm out.txt
