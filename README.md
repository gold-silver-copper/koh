# koh

A Rust, peer-to-peer remote shell inspired by [mosh](https://mosh.org), built on [iroh](https://iroh.computer) / QUIC.

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
koh key info              # show the identity key file and its endpoint id
koh key reset --yes       # delete the identity key; the next use creates a new endpoint id
```

Useful flags:

```sh
--clipboard               # opt in to OSC-52 clipboard writes
--on-bell <cmd>           # run a shell command whenever the remote bell rings
--shell <program>         # host a program instead of the login shell (repeat to pass args)
--key-file <path>         # use a custom identity-key path
--session-ttl-secs <n>    # keep detached sessions around longer/shorter
--max-connections <n>     # limit concurrent connections
--max-sessions <n>        # limit sessions
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

3. Install koh:

   ```sh
   cargo install koh
   ```

If DNS resolution is broken on your Android device, try setting an explicit resolver:

```sh
KOH_DNS=1.1.1.1 koh connect <server-id>
```

To get a phone notification when the remote shell rings the bell (a finished build, an agent
waiting for input), hook `termux-notification`:

```sh
koh connect <server-id> --on-bell 'termux-notification -t "koh bell"'
```

The hook runs detached from the terminal at most once per second; `KOH_BELL_COUNT` and
`KOH_TITLE` are set in its environment, and every other `KOH_*` variable is scrubbed. Bells that
rang before you attached do not fire it; bells during a reconnect do.

## Library

The `koh` crate also builds as a library, but only so the binary, its tests and the fuzz targets
can share code. Its modules are internal and may change in any release; depend on the `koh`
binary, not the library.

## Highlights

- Built in Rust on iroh peer-to-peer QUIC; connects by endpoint id instead of hostname/port.
- Mosh-style predictive local echo and screen-state sync for responsive shells on bad networks.
- Detachable sessions survive suspend/resume, IP changes, and reconnects without tmux.
- No SSH bootstrap, no listening port, and no port forwarding needed.
- Not wire-compatible with mosh or SSH; koh is its own protocol/tool.
- Intended for personal machines you control; not a full SSH replacement.
- Does not provide multi-user accounts, file transfer, scrollback sync, or Windows support.

## Status

koh is experimental and intended for personal use on machines you control.

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the security model, [`SECURITY.md`](SECURITY.md) for vulnerability reporting, and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for implementation details.

## License

MIT, from 0.10.0 onward. Releases before 0.10.0 remain available under GPL-3.0-or-later.
