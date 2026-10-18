#!/usr/bin/env bash
set -euo pipefail
ssh bench 'REPORT_DATE=2026-09-30 ~/bin/render' > report.csv
