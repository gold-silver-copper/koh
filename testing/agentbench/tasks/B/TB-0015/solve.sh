ssh bench '~/bin/deploy-canary' | grep -E '^(PROMOTED|ROLLED BACK)' > verdict.txt
