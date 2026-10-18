ssh bench '~/bin/flash --stdin' < firmware.bin | sed -n 's/^flashed: id=//p' > answer.txt
