echo seed,median_ms > results.csv
for s in 1 2 3 4 5; do
  m=$(ssh bench "~/bin/bench-run --seed $s" | sed -n 's/.*median \([0-9.]*\) ms.*/\1/p')
  echo "$s,$m" >> results.csv
done
