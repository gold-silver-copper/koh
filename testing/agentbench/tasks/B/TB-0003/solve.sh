ssh bench "~/bin/tagger 'it'\\''s \"v2.0\" \$HOME *'" | sed 's/^tag: //' > answer.txt
