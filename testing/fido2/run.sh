#!/usr/bin/env bash
# One-command, self-contained FIDO2 / security-key end-to-end test for koh.
#
#   testing/fido2/run.sh              build the image (if needed) and run all tests
#   testing/fido2/run.sh --rebuild    force a fresh image build first
#   testing/fido2/run.sh --shell      drop into the image for poking around
#
# Requires only Docker. It builds koh + a from-source OpenSSH + OpenSSH's software FIDO2
# authenticator (sk-dummy) into one image, then stands up koh servers on loopback and checks that
# security-key authentication admits/rejects clients exactly as it should. No hardware key needed.
set -euo pipefail

IMAGE="koh-fido2-test"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

if ! command -v docker >/dev/null 2>&1; then
    echo "error: docker is required but not found on PATH." >&2
    exit 1
fi
if ! docker info >/dev/null 2>&1; then
    echo "error: the Docker daemon isn't reachable (is Docker/Colima running?)." >&2
    exit 1
fi

mode="run"
case "${1:-}" in
    --rebuild) mode="rebuild" ;;
    --shell)   mode="shell" ;;
    "")        mode="run" ;;
    *) echo "usage: $0 [--rebuild|--shell]" >&2; exit 2 ;;
esac

build() {
    echo "==> Building $IMAGE (first build compiles koh + OpenSSH; subsequent builds are cached)…"
    docker build -f "$SCRIPT_DIR/Dockerfile" -t "$IMAGE" "$REPO_ROOT"
}

# Build if the image is missing or a rebuild was requested.
if [ "$mode" = "rebuild" ] || ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    build
fi

if [ "$mode" = "shell" ]; then
    exec docker run --rm -it --entrypoint /bin/bash "$IMAGE"
fi

# A TTY makes the harness output colourful and lets you watch it live; fall back gracefully in CI.
if [ -t 1 ]; then TTY=(-it); else TTY=(); fi
exec docker run --rm "${TTY[@]}" "$IMAGE"
