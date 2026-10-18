ssh bench '~/bin/bootstrap' | sed -n 's/^  admin password (shown once, not stored): //p' > password.txt
