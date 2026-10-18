ssh bench '~/bin/clone-engine >/dev/null && cd ~/engine && git bisect start main $(git rev-list --max-parents=0 main) >/dev/null &&
  git bisect run ~/bin/run-case > ~/bisect.log 2>&1; git rev-parse refs/bisect/bad' > answer.txt
