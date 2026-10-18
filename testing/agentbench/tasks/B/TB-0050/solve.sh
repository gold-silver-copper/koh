printf '~/incoming/customers.csv\n\ny\n' | ssh bench 'cat > ~/answers.txt; nohup ~/bin/import-wizard < ~/answers.txt > ~/wizard.out 2>&1 &'
ssh bench 'until grep -q "committed [0-9]* rows" ~/wizard.out; do sleep 1; done'
until ssh bench 'grep -q "committed [0-9]* rows" ~/wizard.out'; do sleep 1; done
