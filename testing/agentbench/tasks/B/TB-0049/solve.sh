ssh bench 'nohup ~/bin/checksum-tree > ct.out 2>&1 < /dev/null &'
ssh bench 'until [ -e ~/.checksum-tree.finished ]; do sleep 1; done'
until ssh bench 'test -e ~/.checksum-tree.finished'; do sleep 1; done
ssh bench 'sed -n "s/^tree digest: //p" ct.out' > digest.txt
