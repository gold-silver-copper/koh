ssh bench 'cat > ~/ed.sh && chmod +x ~/ed.sh' <<'ED'
#!/bin/sh
sed -i -e 's/^workers = .*/workers = 12/' -e 's/^log_level = .*/log_level = debug/' "$1"
ED
ssh -tt bench 'EDITOR=~/ed.sh ~/bin/visconf; rm ~/ed.sh' < /dev/null
