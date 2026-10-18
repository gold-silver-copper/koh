ssh bench '~/bin/train' | sed -n 's/^final loss: //p' > answer.txt
