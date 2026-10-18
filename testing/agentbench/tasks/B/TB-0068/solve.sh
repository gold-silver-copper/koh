ssh bench '~/bin/describe-checkpoint' | grep '^{' | python3 -c 'import json,sys; print(json.load(sys.stdin)["optimizer"]["state"]["resume_token"])' > answer.txt
