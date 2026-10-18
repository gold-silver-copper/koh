ssh bench '~/bin/sync-assets' | tr '\r' '\n' | sed 's/\x1b\[[0-9;]*[A-Za-z]//g' | sed -n 's/^ERROR could not copy \(.*\): .*/\1/p' > failed.txt
