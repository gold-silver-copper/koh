ssh bench '~/bin/export-db | ~/bin/zpack ~/backup/db.z; echo ${PIPESTATUS[0]}' > answer.txt
