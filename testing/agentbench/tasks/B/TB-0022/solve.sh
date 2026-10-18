ssh bench 'cd ~/configs && for f in *; do
  timeout 15 validate-cfg "$f" > /dev/null 2> err.$$; s=$?
  if [ $s = 0 ]; then o=ok; elif [ $s = 124 ]; then o=hang; elif grep -q Traceback err.$$; then o=crash; elif [ $s = 2 ]; then o=invalid; else o=unknown; fi
  echo "$f: $o"; rm -f err.$$
done' > report.txt
