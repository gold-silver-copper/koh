printf 'break 33\nrun\nc\nc\nc\nc\nprint r3\nquit\n' | ssh bench '~/bin/tdb ~/vm/solver.prog' | grep -o 'r3 = [0-9-]*' | tail -1 | cut -d' ' -f3 > answer.txt
