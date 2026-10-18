ssh bench 'cd ~/"scenes/forest night" && FRAME=1042 ~/bin/render-frame' | sed -n 's/.*checksum //p' > answer.txt
