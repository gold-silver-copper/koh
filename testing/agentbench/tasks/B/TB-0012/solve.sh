ssh bench '~/bin/lint-legacy 2>&1 >/dev/null | grep -c "^warning\[deprecated\]:"' > answer.txt
