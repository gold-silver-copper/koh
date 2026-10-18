ssh bench '~/bin/audit-perms' | awk 'NR>1 && $2=="nobody" && substr($1,9,1)=="w" {n++} END {print n}' > answer.txt
