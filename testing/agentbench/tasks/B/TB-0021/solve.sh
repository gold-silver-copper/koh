ssh bench '~/bin/queue-worker >/dev/null 2>&1; grep " FATAL " ~/logs/queue-worker.log' > fatal.txt
