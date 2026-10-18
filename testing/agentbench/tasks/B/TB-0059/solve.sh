ssh bench 'git clone -q ~/project.bundle ~/project && cd ~/project &&
  git bisect start main "$(git rev-list --max-parents=0 main)" > /dev/null &&
  git bisect run ./run-tests > ../bisect.log 2>&1;
  sed -n "s/^\([0-9a-f]\{40\}\) is the first .\{0,1\}bad.\{0,1\} commit$/\1/p" ../bisect.log' > answer.txt
