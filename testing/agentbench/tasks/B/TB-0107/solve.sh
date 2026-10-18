# run in the foreground; after the drop kills it, resume detached and wait
ssh bench '~/bin/train-model'
ssh bench 'setsid nohup ~/bin/train-model --resume > train.log 2>&1 < /dev/null &'
until ssh bench 'while [ ! -e ~/model/final.json ]; do sleep 0.5; done'; do sleep 1; done
