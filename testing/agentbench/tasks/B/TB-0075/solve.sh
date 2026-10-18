ssh bench '~/bin/deploy-canary > canary.log; echo $?' > status.txt
ssh bench 'grep -o "^\(PROMOTED\|ROLLED BACK\|ABORTED\)" canary.log' > answer.txt
cat status.txt >> answer.txt
rm status.txt
