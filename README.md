# koh2

An SSH-authenticated, peer-to-peer remote shell inspired by [mosh](https://mosh.org), built on [iroh](https://iroh.computer) / QUIC.

koh2 keeps the mosh-style user experience — a simple `koh user@host` command, predictive local echo, reconnects, and detachable sessions — but uses [iroh-ssh](https://github.com/rustonbsd/iroh-ssh) for SSH authentication without exposing a public TCP SSH port.

## Install

Install both binaries on both machines:

```sh
cargo install iroh-ssh
cargo install --git https://github.com/gold-silver-copper/koh --branch koh2
```

If you are working from a checkout of this branch:

```sh
cargo install --path .
```

## Usage

On the server, run `iroh-ssh` in front of the local SSH daemon:

```sh
iroh-ssh server --persist
```

It prints an address like:

```sh
iroh-ssh user@<iroh-ssh-endpoint-id>
```

On the client, connect with koh:

```sh
koh user@<iroh-ssh-endpoint-id>
```

Run a remote command instead of the login shell:

```sh
koh user@<iroh-ssh-endpoint-id> -- tmux attach
```

Useful options:

```sh
koh --clipboard user@<id>
koh --key-file <path> user@<id>
koh --ssh "iroh-ssh -i ~/.ssh/id_ed25519" user@<id>
koh --server /path/to/koh user@<id>
```

## How it works

1. `iroh-ssh` reaches the server over iroh, not public TCP port 22.
2. SSH authenticates you against the server's local `sshd`.
3. SSH launches a temporary remote `koh serve`.
4. koh attaches to that temporary server over koh's own iroh/QUIC terminal-sync protocol.

## Highlights

- Mosh-style CLI: `koh [options] [--] user@host [command...]`.
- SSH authentication and account selection, carried over iroh.
- No manual port forwarding, VPN, or Tailscale required.
- Mosh-style predictive local echo and screen-state sync for bad networks.
- Detachable sessions survive suspend/resume, IP changes, and reconnects.
- Not wire-compatible with mosh or SSH; koh uses its own terminal protocol over iroh.
- Does not provide file transfer, scrollback sync, or Windows support.

## Android / Termux

1. Install Termux from the [Termux GitHub releases](https://github.com/termux/termux-app/releases). Do not use the old Play Store build.
2. Install Rust and build tools:

   ```sh
   pkg update
   pkg install rust clang pkg-config
   ```

3. Install both binaries:

   ```sh
   cargo install iroh-ssh
   cargo install --git https://github.com/gold-silver-copper/koh --branch koh2
   ```

If DNS resolution is broken on Android, try:

```sh
KOH_DNS=1.1.1.1 koh user@<iroh-ssh-endpoint-id>
```

## Status

koh2 is experimental and intended for personal machines you control.

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md), [`SECURITY.md`](SECURITY.md), and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for details.

## License

GPL-3.0-or-later.
