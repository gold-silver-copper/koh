# Tier 2 — network-realism tests (Docker)

Scaffolding to test the parts of rmosh that need real network topology: the **relay path**,
**NAT traversal**, **OS-level chaos**, and **roaming / connection migration**. A single Linux
host with Docker fakes "two machines + a relay" by putting the server and client on separate
bridge networks that meet only through a self-hosted iroh relay.

> **Status:** this directory is runnable scaffolding for whoever has Docker + Linux. It is
> **not executed by `cargo test`** and was **not run in the environment that generated it** —
> treat the exact `iroh-relay` invocation and the docker-network names as things to verify
> against your versions (see caveats). Tiers 0 and 1 (in `cargo test`) are the verified layers;
> this is the network-realism layer on top.

## What's here

| File | Purpose |
|---|---|
| `Dockerfile` | builds `rmosh-server` + `rmosh-client`, installs `iroh-relay`, and bundles `tc`/`iptables`/`expect` |
| `docker-compose.yml` | relay + server + client on separate networks (`servernet`, `clientnet`, shared `relaynet`) |
| `scripts/run-server.sh` | starts the server pointed at the relay; prints the endpoint id |
| `scripts/netem.sh` | injects latency/jitter/loss/reorder/dup on a container link with `tc qdisc netem` |
| `scripts/drive.exp` | drives the client TUI (via a PTY) typing markers before/after a roam |
| `scripts/roaming-test.sh` | host orchestration: start a session, move the client's network mid-session, assert it resumes |

## Run it

```sh
# from the workspace root
docker compose -f testing/tier2/docker-compose.yml up --build -d

# 1) relay path: start the server (it dials nothing; clients reach it via the relay)
docker compose -f testing/tier2/docker-compose.yml exec server /scripts/run-server.sh
#    -> note the printed endpoint id

# 2) OS-level chaos beneath iroh's real QUIC stack (complements the Tier-0 in-process sim)
docker compose -f testing/tier2/docker-compose.yml exec client /scripts/netem.sh eth0 120 40 8 25

# 3) roaming / connection migration (the headline Tier-2 test) — run on the host
./testing/tier2/scripts/roaming-test.sh
```

`roaming-test.sh` starts a session over the relay, confirms a command round-trips
(`ROAM_BEFORE_MARKER`), then `docker network disconnect`/`connect`s the client onto a fresh
network (new IP) mid-session, and asserts a second command still round-trips
(`ROAM_AFTER_MARKER`) — i.e. QUIC migration resumed the session and re-synced to the current
screen. This is the property that makes rmosh a *mosh*, and containers are the only practical
way to automate it.

## NAT traversal (extension)

To force hole-punching to do real work, put an `iptables` MASQUERADE/NAT in front of the
client container (drop direct inbound, allow only the relay path initially) and confirm a
direct path is still established. Add a `nat` service or an `iptables` rule in
`run-server.sh`/an init script; this is left as an extension because the exact rules depend on
your bridge layout.

## Caveats to verify before relying on this

- **`iroh-relay --dev`**: the compose runs the relay in a dev/HTTP mode at `http://relay:3340`.
  Confirm the flag and port against your installed `iroh-relay --help`; production relays use
  TLS and `https://`. The endpoints take `--relay-url`, which accepts `http(s)://host:port`.
- **docker network names** in `roaming-test.sh` (`tier2_clientnet`, `tier2_clientnet2`) follow
  Compose's `<project>_<network>` convention; adjust if your project name differs.
- **`cargo install iroh-relay --version 1.0.0`** must resolve a binary; pin to the iroh line in
  the root `Cargo.toml`.
