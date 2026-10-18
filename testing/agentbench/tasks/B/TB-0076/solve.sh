ssh bench '~/bin/bake-lighting > light.log & ~/bin/compile-shaders > shade.log; wait'
ssh bench 'echo "lighting: $(sed -n "s/.*checksum //p" light.log)"; echo "shaders: $(sed -n "s/^compiled \([0-9]*\) .*/\1/p" shade.log)"' > answer.txt
