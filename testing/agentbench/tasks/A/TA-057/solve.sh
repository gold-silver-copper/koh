#!/usr/bin/env bash
set -euo pipefail
ssh bench 'cd ~/crates/textstats && sed -i "s/    s.split(.\\\\n.).count()/    s.lines().count()/" src/lib.rs && cargo test --offline -q'
