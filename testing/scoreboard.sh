#!/bin/sh
# koh's scoreboard: builds koh and the bench, and writes docs/SCOREBOARD.md. mosh and ssh are
# measured when mosh-server, mosh-client, ssh, sshd and ssh-keygen are on PATH, and instructions
# when perf (or valgrind) is. See testing/bench/README.md.
#
#   testing/scoreboard.sh [ARGS...]
#
# ARGS go to koh-bench: --recordings all|none|a,b, --systems koh,mosh,ssh, --samples N,
# --skip wire,latency,memory,instructions, --out FILE.
set -eu
root=$(git rev-parse --show-toplevel)
cd "$root"
cargo build --quiet --release --locked
cargo build --quiet --release --manifest-path testing/bench/Cargo.toml
exec testing/bench/target/release/koh-bench --koh target/release/koh "$@"
