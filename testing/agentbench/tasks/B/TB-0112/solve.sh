ssh bench '~/bin/long-build > build.log & while ! ~/bin/lockinfo > /dev/null; do sleep 0.2; done; ~/bin/lockinfo; wait' | sed -n 's/.*token //p' > answer.txt
