ssh bench 'EDITOR="sed -i -e \"/old-db.internal/d\" -e \"/cache-1.internal/a 10.0.4.7    cache-2.internal cache-2\"" ~/bin/edit-hosts'
