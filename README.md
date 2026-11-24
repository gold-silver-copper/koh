# koh

Ultra-minimal peer-to-peer remote shell, headless jobs, delta file sync, and interactive
[`fux`](https://github.com/gold-silver-copper/fux) sessions over [iroh](https://iroh.computer) QUIC.

Rewritten from scratch on `fux` 0.43, `fux-vt` 0.20, and `fuxix` 0.12 (~5,800 lines, down from ~22,000):

- **Layer 1 — Transport & Scoped Auth:** iroh QUIC (`koh/18`) with TLS-bound Ed25519 client proofs,
  compatible with existing `~/.config/koh/{client.key,server.key,servers,clients}` files, QR codes
  on `koh serve` / `koh id --qr`, and `--cp`/`--exec` path-scoped keys.
- **Layer 2 — Raw Streams & Delta Sync (no PTY):**
  - `koh exec`: raw separate stdout/stderr, binary-clean, stdin EOF, SIGHUP on disconnect.
  - `koh run` / `jobs` / `logs` / `wait` / `kill`: detached headless jobs backed by raw append-only
    log files (no 80-column wrapping, no screen truncation). The server ends them with `kill(1)`,
    which must be on its `PATH`; so must `id(1)` where `XDG_RUNTIME_DIR` is not set.
  - `koh cp` / `--sync`: `blake3` delta file sync (single or multi-source, `--delete`, `--exclude`,
    `-p`, `--dry-run`).
- **Layer 3 — Interactive Sessions Backed Directly by `fux`:**
  - Every remote session writes a `fux` pane folder on the server (kept by `koh serve`, not by a
    `fux` holder) and streams row-level `FrameDelta` updates and once-per-ID `pic-N.sixel` blobs
    over QUIC.
  - Sixel is the one picture format, as in `fux` 0.43. A program that draws with the Kitty
    graphics protocol alone (`kitten icat`) shows nothing in a session, and a picture is drawn
    only in a terminal that draws sixel.
  - Automatic reconnect with exponential backoff on network drops/roaming (`koh connect` and
    `koh mount`, 64 KiB `in` FIFO buffering while reconnecting).
  - `koh connect` embeds `fux::view` directly in-process — one single renderer for sixel pictures,
    OSC 8 hyperlinks, OSC 52 clipboard, OSC 12 cursor colour, host colours, and Kitty keyboard
    protocol. Detach locally with `Ctrl-] .` or `C-b d`; `Ctrl-] Ctrl-]` and `C-b C-b` type the
    key itself.
  - `koh mount SERVER [DIR]` mirrors a remote session into a local pane folder so unmodified local
    `fux view` renders remote panes beside local ones: `DIR`, or with none `main/koh-SERVER` in
    the default `fux` session (`$XDG_RUNTIME_DIR/fux`, else `~/.cache/fux`). No `FUX_DIR` is
    read. A mirror has no `status` file: its program and its holder are on the server.
  - `koh sessions`, `koh output --last`, and `koh wait --session N` use **OSC 133 `marks`**
    (`fux-vt::Term::marks()`).

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
