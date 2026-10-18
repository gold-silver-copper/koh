#!/usr/bin/env bash
set -euo pipefail
ssh bench 'cp -p ~/app/config/config.yaml ~/app/config/config.yaml.bak'
scp -q config.yaml bench:app/config/config.yaml
