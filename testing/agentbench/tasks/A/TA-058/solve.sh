#!/usr/bin/env bash
set -euo pipefail
scp -q "$(dirname "$0")/solve-main.rs" bench:crates/logsum/src/main.rs
ssh bench 'cd ~/crates/logsum && cargo build --release --offline -q && mkdir -p ~/out && ./target/release/logsum ~/data/*.log > ~/out/summary.txt'
