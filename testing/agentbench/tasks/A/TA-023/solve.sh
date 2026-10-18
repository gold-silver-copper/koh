#!/usr/bin/env bash
set -euo pipefail
ssh bench '~/bin/totals' < orders.csv > totals.txt
