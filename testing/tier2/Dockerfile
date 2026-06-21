# Tier 2 image: rmosh server/client + a self-hosted iroh relay + Linux network tooling
# (tc/netem, iptables) so a single host can fake "two machines + a relay" for relay-path,
# NAT-traversal, OS-level chaos, and roaming/migration tests.
#
# Build context is the workspace root:
#   docker build -f testing/tier2/Dockerfile -t rmosh-tier2 .

# --- builder ---------------------------------------------------------------
FROM rust:1-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --release -p rmosh-server -p rmosh-client
# The runnable iroh relay server. Pin to the same iroh line the workspace uses.
RUN cargo install iroh-relay --version 1.0.0 --locked --root /relay

# --- runtime ---------------------------------------------------------------
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 iptables iputils-ping ca-certificates tini procps expect \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/rmosh-server /usr/local/bin/rmosh-server
COPY --from=builder /src/target/release/rmosh-client /usr/local/bin/rmosh-client
COPY --from=builder /relay/bin/iroh-relay /usr/local/bin/iroh-relay
COPY testing/tier2/scripts/ /scripts/
RUN chmod +x /scripts/*.sh
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["sleep", "infinity"]
