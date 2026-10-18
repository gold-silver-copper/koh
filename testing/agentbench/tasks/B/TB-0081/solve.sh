report=$(ssh bench '~/bin/physics-sim 2>&1 >/dev/null' | sed -n 's/^crash report written to //p')
ssh bench "grep -A1 '^faulting frame' '$report' | tail -1" | awk '{print $2}' > answer.txt
