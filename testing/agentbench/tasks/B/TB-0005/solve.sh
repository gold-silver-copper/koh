until ssh bench '~/bin/fetch-index' > out.txt; do :; done
sed -n 's/^index checksum: //p' out.txt > answer.txt
rm -f out.txt
