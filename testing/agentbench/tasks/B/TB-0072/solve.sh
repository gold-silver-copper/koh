ssh bench '~/bin/notes-gen' | grep -a '^RELEASE-TAG: ' | sed 's/^RELEASE-TAG: //' > answer.txt
