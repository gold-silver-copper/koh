ssh bench '~/bin/invsh' > out.txt <<'SQL'
select 'ANS=' || count(*) as a from stock s join items i on i.sku = s.sku join warehouses w on w.id = s.warehouse_id where w.code = 'east' and s.qty < i.reorder_level;
select 'ANS=' || s.sku as a from stock s join items i on i.sku = s.sku join warehouses w on w.id = s.warehouse_id where w.code = 'east' and s.qty < i.reorder_level order by i.reorder_level - s.qty desc limit 1;
.quit
SQL
sed 's/^\(inv> \)*//' out.txt | grep -o '^ANS=.*' | sed 's/^ANS=//' > answer.txt
rm -f out.txt
