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

## Highlights

- Built in Rust on iroh peer-to-peer QUIC; connects by endpoint id instead of hostname/port.
- Mosh-style predictive local echo and screen-state sync for responsive shells on bad networks.
- Detachable sessions survive suspend/resume, IP changes, and reconnects without tmux.
- No SSH bootstrap, no listening port, and no port forwarding needed.
- Intended for personal machines you control; not a full SSH replacement.
- Does not provide multi-user accounts, file transfer, scrollback sync, or Windows support.

## Status

koh is experimental and intended for personal use on machines you control.

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the security model, [`SECURITY.md`](SECURITY.md) for vulnerability reporting, and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for implementation details.

## License

GPL-3.0-or-later, matching upstream mosh.
