ssh bench '~/bin/checkout-project'
mkdir -p backup
rsync -a bench:project backup/
