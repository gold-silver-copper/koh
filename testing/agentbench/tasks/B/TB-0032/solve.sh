ssh bench 'f=~/.deployd/authorized_keys; [ -n "$(tail -c1 "$f")" ] && echo >> "$f"; cat >> "$f"; chmod 700 ~/.deployd; chmod 600 "$f"' < deploy_key.pub
