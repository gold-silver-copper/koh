ssh bench '~/bin/emit-events' | python3 redact.py | ssh bench '~/bin/load-events'
