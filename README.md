# koh

Ultra-minimal peer-to-peer remote shell, headless jobs, delta file sync, and interactive
[`fux`](https://github.com/gold-silver-copper/fux) sessions over [iroh](https://iroh.computer) QUIC.

Rewritten from scratch on `fux-vt` 0.19 and `fuxix` 0.11 (~4,000 lines, down from ~22,000):

- **Layer 1 — Transport & Scoped Auth:** iroh QUIC with TLS-bound Ed25519 client proofs, compatible
  with existing `~/.config/koh/{client.key,server.key,servers,clients}` files and `--cp`/`--exec`
  path-scoped keys.
- **Layer 2 — Raw Streams & Delta Sync (no PTY):**
  - `koh exec`: raw separate stdout/stderr, binary-clean, stdin EOF, SIGHUP on disconnect.
  - `koh run` / `jobs` / `logs` / `wait` / `kill`: detached headless jobs backed by raw append-only
    log files (no 80-column wrapping, no screen truncation).
  - `koh cp` / `--sync`: `blake3` delta file sync (`--delete`, `--exclude`, `-p`, `--dry-run`).
- **Layer 3 — Interactive Sessions Backed by New `fux` Panes:**
  - Every remote session writes a genuine frozen v1 `fux` pane folder on the server and pushes
    screen snapshots immediately over QUIC (zero double-polling).
  - `koh sessions`, `koh output --last`, and `koh wait --session N` use **OSC 133 `marks`**
    (`fux-vt::Term::marks()`), replacing brittle PTY-activity heuristics.
  - `koh mount` mirrors a remote session into a local `$FUX_DIR` pane folder so unmodified local
    `fux view` renders remote panes beside local ones.

## Quick start

```sh
# Client: print endpoint id
koh id

# Server: allow client and start serving
koh clients add laptop <client-id>
koh serve

# Client: save server and use it
koh servers add box <server-id>
koh exec box -- uname -a
koh exec box --sync proj -- cargo test
koh run box --name build -- make -j4 && koh wait box build
koh cp -r --exclude target ./src box:proj/
koh connect box
koh mount box   # mirror remote session into local fux workspace
```

Run `koh --help` (or `koh help-agents`) for the complete command reference and exit-code contract.
