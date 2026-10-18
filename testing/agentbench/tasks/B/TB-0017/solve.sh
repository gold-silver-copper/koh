ssh bench '~/bin/request-cert api.internal'
ssh bench 'until [ -e ~/certs/api.internal.crt ]; do sleep 1; done'
scp -q bench:certs/api.internal.crt api.internal.crt
