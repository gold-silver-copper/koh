ssh bench 'grep -n "\"12,5\"" ~/data/orders.csv | head -1 | cut -d: -f2-' > bad-row.txt
