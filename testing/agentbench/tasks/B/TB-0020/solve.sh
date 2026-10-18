ssh bench '~/bin/render-frames > out.txt; echo $?; tail -n1 out.txt | awk "{print \$2}"' > answer.txt
