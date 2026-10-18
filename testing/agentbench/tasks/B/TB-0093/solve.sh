ssh bench 'cp -p ~/svc/api.key ~/svc/api.key.prev'
scp -q new-api.key bench:svc/api.key
ssh bench 'chmod 600 ~/svc/api.key ~/svc/api.key.prev && ~/bin/svc-reload'
