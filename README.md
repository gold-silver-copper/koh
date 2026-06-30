# koh2

An SSH-authenticated, peer-to-peer remote shell inspired by [mosh](https://mosh.org), built on [iroh](https://iroh.computer) / QUIC.

koh2 uses [iroh-ssh](https://github.com/rustonbsd/iroh-ssh) to authenticate and launch a one-shot remote `koh` server without a public TCP SSH port. The interactive shell then attaches over koh's own iroh/QUIC protocol.

## Install and usage

Install both binaries on both machines:

```sh
cargo install iroh-ssh
cargo install --path .
```

On the server, run iroh-ssh in front of the local SSH daemon:

```sh
iroh-ssh server --persist
```

It prints an endpoint id like:

```sh
iroh-ssh user@<iroh-ssh-endpoint-id>
```

On the client, connect with a mosh-style command:

```sh
koh user@<iroh-ssh-endpoint-id>
```

Run a remote command instead of the login shell:

```sh
koh user@<iroh-ssh-endpoint-id> -- tmux attach
```

Flow:

1. iroh-ssh connects to the server over iroh, not TCP port 22.
2. SSH authenticates you against the server's local `sshd`.
3. SSH launches a temporary remote `koh serve`.
4. koh2 attaches to that temporary server over iroh/QUIC.

Useful options:

```sh
koh --clipboard user@<id>
koh --key-file <path> user@<id>
koh --ssh "iroh-ssh -i ~/.ssh/id_ed25519" user@<id>
koh --server /path/to/koh user@<id>
```

Keys live under `~/.config/koh/` by default.

**Platforms:** Linux, macOS, and Android via [Termux](https://termux.dev). Windows is not supported; use WSL2.

## Android / Termux install

1. Install Termux from the [Termux GitHub releases](https://github.com/termux/termux-app/releases). Do not use the old Play Store build.
2. In Termux, install Rust and build tools:

   ```sh
   pkg update
   pkg install rust clang pkg-config
   ```

3. From a koh2 checkout, install both binaries:

   ```sh
   cargo install iroh-ssh
   cargo install --path .
   ```

If DNS resolution is broken on your Android device, try setting an explicit resolver:

```sh
KOH_DNS=1.1.1.1 koh user@<iroh-ssh-endpoint-id>
```

## Highlights

- Mosh-style CLI: `koh [options] [--] user@host [command...]`.
- SSH authentication and account selection, carried over iroh instead of a public TCP SSH port.
- The shell session runs over koh's peer-to-peer iroh/QUIC protocol after bootstrap.
- Mosh-style predictive local echo and screen-state sync for responsive shells on bad networks.
- Detachable sessions survive suspend/resume, IP changes, and reconnects without tmux.
- No manual port forwarding, VPN, or Tailscale required.
- Not wire-compatible with mosh or SSH; koh uses its own terminal sync protocol over iroh.
- Does not provide file transfer, scrollback sync, or Windows support.

## Status

koh2 is experimental and intended for personal use on machines you control.

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the security model, [`SECURITY.md`](SECURITY.md) for vulnerability reporting, and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for implementation details.

## License

GPL-3.0-or-later.
