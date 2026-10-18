id=$(ssh bench '~/bin/qsub ~/jobs/retarget.spec' | awk '{print $3}')
ssh bench "~/bin/qstat --wait $id" | sed 's/.*result=//' > answer.txt
