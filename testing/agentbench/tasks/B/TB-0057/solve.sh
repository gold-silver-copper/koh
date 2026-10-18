ssh bench '~/bin/start-app'
ssh bench 'sleep 1; for f in /proc/[0-9]*/fd/*; do [ "$(readlink "$f" 2>/dev/null)" = "$HOME/app/logs/debug.log" ] && echo "${f#/proc/}"; done | cut -d/ -f1 | sort -u | xargs kill; sleep 0.5; : > ~/app/logs/debug.log; ~/bin/app-ping'
