ssh bench 'nohup ~/bin/pair-device > pair.out 2>&1 < /dev/null &'
ssh bench 'until grep -q "^Pairing code:" pair.out; do sleep 0.2; done; ~/bin/confirm-pair "$(sed -n "s/^Pairing code: \([0-9-]*\).*/\1/p" pair.out | tail -1)"'
