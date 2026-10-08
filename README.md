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

# On the server, allow that client by name, and start a shell host (it prints its own id):
koh clients add phone <client-id>
koh serve

# On the client, save the server by name, and connect:
koh servers add laptop <server-id>
koh connect laptop
```

Or run `koh` alone on a terminal for a menu of this machine's keys, the servers it connects to
and the clients allowed here: pick one by number to connect, rename or delete it; `a` adds one,
`k` shows both keys in full with QR codes and resets one, saying first who will lose access.

Useful commands:

```sh
koh                       # on a terminal: the menu of keys, servers and clients
koh id                    # print this machine's endpoint id (its client key's)
koh servers               # the servers you connect to: add <name> <id>, rm <name>, rename <old> <new>
koh clients               # the clients allowed here, likewise
koh serve                 # host a shell for the saved clients (--allow <id> adds one for this run)
koh connect <name|id>     # connect to a saved server, or to a server id
koh key info              # show both identity key files and their endpoint ids
koh key reset [client|server] --yes  # delete a key (client by default); the next use makes a new id
```

Useful flags:

```sh
--no-clipboard            # ignore the server's OSC-52 clipboard writes (on by default)
--no-hyperlinks           # paint the server's hyperlinks as plain text (links on by default)
--no-colours              # don't tell the server your terminal's colours (told by default, so
                          # vim, bat and delta pick a matching theme)
--on-bell <cmd>           # run a shell command whenever the remote bell rings
--shell <program>         # host a program instead of the login shell (repeat to pass args)
--key-file <path>         # use a custom identity-key path
--session-ttl-secs <n>    # keep detached sessions around longer/shorter
--max-connections <n>     # limit concurrent connections
--max-sessions <n>        # limit sessions
```

Keys live under `~/.config/koh/` by default (`client.key`, `server.key`), and the names beside
them: `servers` beside the client key and `clients` beside the server key, one `name id` a line
(`#` comments allowed). They are checked as the keys are, since `clients` decides who may open a
shell: a file that is a symlink or someone else's is refused, and a loose mode is tightened.

**Keys, mouse and pastes** reach the remote program as it asked, whatever terminal you type on: the
client decodes what your terminal sends (it turns on the kitty keyboard protocol in a terminal that
speaks it, so Ctrl-I and Tab, or Shift-Enter and Enter, stay apart) and the server encodes each key
for the program, kitty's encoding to nvim or helix, legacy bytes to the rest.

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
- Scrollback: `Ctrl-^ [` opens the server's history above the live screen, in full colour, with
  the arrows, Page Up/Down, the mouse wheel, `/` to search and `q` to leave; new output keeps
  arriving below.
- Does not provide multi-user accounts, file transfer, or Windows support.

## Status

koh is experimental and intended for personal use on machines you control.

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the security model, [`SECURITY.md`](SECURITY.md) for vulnerability reporting, and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for implementation details.

## License

MIT, from 0.10.0 onward. Releases before 0.10.0 remain available under GPL-3.0-or-later.
