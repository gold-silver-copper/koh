ssh bench '~/bin/disk-report --all' | awk 'NR>1 {p=$5; sub("%","",p); if (p+0>m) {m=p+0; $1=$2=$3=$4=$5=""; l=$0}} END {sub(/^ +/,"",l); print l}' > answer.txt
