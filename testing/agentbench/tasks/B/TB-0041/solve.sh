printf 'break mix\nrun\ncontinue\ncontinue\ncontinue\ncontinue\nprint r3\nquit\n' | ssh bench '~/bin/vmdbg ~/prog.vm' | grep -o 'r3 = [0-9]*' | tail -1 | cut -d' ' -f3 > answer.txt
