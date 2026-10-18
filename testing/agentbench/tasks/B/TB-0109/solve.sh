python3 gen_capture.py
for try in 1 2 3; do
  ssh bench '~/bin/receive-capture' < capture.bin && break
done
