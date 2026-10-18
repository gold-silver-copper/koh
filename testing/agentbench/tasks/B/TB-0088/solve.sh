python3 gen_dataset.py
ssh bench 'mkdir -p ~/data/incoming'
scp -q dataset.bin bench:data/incoming/dataset.bin
ssh bench '~/bin/register-dataset ~/data/incoming/dataset.bin'
