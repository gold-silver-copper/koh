#!/usr/bin/env bash
set -euo pipefail
KEY=$(sed -n '/^----- name -----$/{n;p}' <<'EOF'
----- name -----
O'Brien & Sons "Ltd" $HOME\n #1;`date`
----- end -----
EOF
)
ssh bench "~/bin/lookup $(printf %q "$KEY")" | sed -n 's/^code: //p' > answer.txt
