ssh bench 'nohup ~/bin/backup-home > backup.log 2>&1 < /dev/null &'
ssh bench 'while [ ! -e ~/backup/summary.txt ]; do sleep 1; done'
until ssh bench 'test -e ~/backup/summary.txt'; do sleep 1; done
scp -q bench:backup/summary.txt summary.txt
