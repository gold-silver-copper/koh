ssh bench 'nohup ~/bin/token-server > tok.out 2>&1 < /dev/null &'
ssh bench 'until grep -q "^challenge #" tok.out; do sleep 0.2; done'
n=$(ssh bench 'grep "^challenge #" tok.out | tail -1 | sed "s/^challenge #\([0-9]*\):.*/\1/"')
{
  for i in 0 1 2; do
    k=$((n + i))
    ssh bench "until grep -q '^challenge #$k:' tok.out; do sleep 0.2; done; sed -n 's/^challenge #$k: //p' tok.out"
  done
} | ssh bench '~/bin/gatekeeper'
ssh bench 'kill -INT "$(cat ~/.tokens/pid)"; while kill -0 "$(cat ~/.tokens/pid)" 2>/dev/null; do sleep 0.2; done'
