# koh

A Rust, peer-to-peer reimplementation of [mosh](https://mosh.org) built on [iroh](https://iroh.computer) / QUIC.

koh gives you a responsive remote shell that survives network changes, suspend/resume, and reconnects — without SSH, open ports, or server-side accounts.

## Tech stack

- Rust
- iroh peer-to-peer QUIC transport
- Unix PTYs
- mosh-style terminal state synchronization and predictive local echo
- Encrypted local identity keys
- Linux, macOS, and Android/Termux

## Why

SSH is universal, but it is not ideal on mobile or unreliable networks. mosh fixed responsiveness and roaming, but still depends on SSH and reachable UDP.

koh explores a smaller model for personal machines you control:

- connect by peer id
- no listening port
- no SSH bootstrap
- predictive local echo
- detachable sessions
- peer-to-peer NAT traversal via iroh

koh is not an SSH replacement. It is a focused, mobile-friendly interactive shell.

## Install

```sh
cargo install koh
```

Or from git:

```sh
cargo install --git https://github.com/gold-silver-copper/koh
```

From a checkout:

```sh
cargo build --release
```

**Platforms:** Linux, macOS, and Android via [Termux](https://termux.dev). Windows is not supported; use WSL2.

## Usage

koh authorizes by endpoint id. There are no passwords or accounts.

On the client, print its id:

```sh
koh id
```

On the server, allow that client and start a shell host:

```sh
koh serve --allow <client-id>
```

On the client, connect to the server:

```sh
koh connect <server-id>
```

Useful commands:

```sh
koh id                    # print this machine's endpoint id
koh serve --allow <id>    # host a shell for an allowed client
koh connect <id>          # connect to a server id
koh key passwd            # change the identity-key passphrase
koh key info              # show identity-key information
```

Useful flags:

```sh
--clipboard               # opt in to OSC-52 clipboard writes
--key-file <path>         # use a custom identity-key path
--session-ttl-secs <n>    # keep detached sessions around longer/shorter
--max-connections <n>     # limit concurrent connections
--max-sessions <n>        # limit sessions
```

Keys live under `~/.config/koh/` by default.

## Comparison

| Feature | koh | mosh | OpenSSH | Eternal Terminal | wush |
|---|---:|---:|---:|---:|---:|
| Predictive local echo | ✅ | ✅ | ❌ | ❌ | ❌ |
| Reconnect after network change | ✅ | ✅ | ❌ | ✅ | ⚠️ |
| Detach / reattach session | ✅ | ❌ | ❌ | ✅ | ❌ |
| No listening port | ✅ | ❌ | ❌ | ❌ | ✅ |
| Peer-to-peer transport | ✅ | ❌ | ❌ | ❌ | ✅ |
| File transfer | ❌ | ❌ | ✅ | ❌ | ✅ |
| Port forwarding | ❌ | ❌ | ✅ | ✅ | ❌ |
| Multi-user accounts | ❌ | ✅ | ✅ | ✅ | ❌ |
| Main transport | iroh QUIC | UDP + SSH bootstrap | TCP/SSH | TCP + SSH bootstrap | WireGuard/DERP |

Choose **koh** if you want a mobile-friendly, mosh-like shell over peer-to-peer QUIC.

Choose **mosh** if you want the mature, packaged-everywhere version of predictive roaming and already have SSH access.

Choose **OpenSSH** if you need accounts, file transfer, tunnels, agent forwarding, FIDO2, PAM, jump hosts, or mature infrastructure.

Choose **Eternal Terminal** if you want SSH-based reconnects, scrollback, and port forwarding.

Choose **wush** if you primarily want peer-to-peer file transfer.

## Status

koh is experimental and intended for personal use on machines you control.

Major limitations:

- no SSH compatibility
- no multi-user account model
- no file transfer
- no port forwarding
- no scrollback sync
- no Windows support

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the security model, [`SECURITY.md`](SECURITY.md) for vulnerability reporting, and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for implementation details.

## License

GPL-3.0-or-later, matching upstream mosh.
