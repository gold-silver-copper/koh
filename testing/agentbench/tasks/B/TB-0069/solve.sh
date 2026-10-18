ssh bench '~/bin/train-epochs' | tr '\r' '\n' > out.txt
grep -c 'loss=nan' out.txt > answer.txt
sed -n 's/.*val_loss=//p' out.txt | tail -1 >> answer.txt
rm out.txt
