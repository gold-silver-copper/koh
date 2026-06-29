# koh

A Rust, peer-to-peer reimplementation of [mosh](https://mosh.org) built on [iroh](https://iroh.computer) / QUIC.

koh gives you a responsive remote shell that survives network changes, suspend/resume, and reconnects — without SSH, open ports, or server-side accounts.

## Install and usage

```sh
cargo install koh
```

koh authorizes by endpoint id. There are no passwords or accounts.

```sh
# On the client, print its id:
koh id

# On the server, allow that client and start a shell host:
koh serve --allow <client-id>

# On the client, connect to the server:
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

**Platforms:** Linux, macOS, and Android via [Termux](https://termux.dev). Windows is not supported; use WSL2.

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

## Comparison

| Feature | koh | mosh | OpenSSH | Eternal Terminal | wush |
|---|---:|---:|---:|---:|---:|
| Predictive local echo | ✅ | ✅ | ❌ | ❌ | ❌ |
| Reconnect after network change | ✅ | ✅ | ❌ | ✅ | ⚠️ |
| Detach / reattach session | ✅ | ❌ | ❌ | ✅ | ❌ |
| No listening port | ✅ | ❌ | ❌ | ❌ | ✅ |
| File transfer | ❌ | ❌ | ✅ | ❌ | ✅ |
| No port forwarding needed | ✅ | ❌ | ❌ | ❌ | ✅ |
| Multi-user accounts | ❌ | ✅ | ✅ | ✅ | ❌ |
| Main transport | iroh QUIC | UDP + SSH bootstrap | TCP/SSH | TCP + SSH bootstrap | WireGuard/DERP |

Choose **koh** if you want a mobile-friendly, mosh-like shell over peer-to-peer QUIC.


## Status

koh is experimental and intended for personal use on machines you control.

Major limitations:

- no SSH compatibility
- no multi-user account model
- no file transfer
- no scrollback sync
- no Windows support

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the security model, [`SECURITY.md`](SECURITY.md) for vulnerability reporting, and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for implementation details.

## License

GPL-3.0-or-later, matching upstream mosh.
