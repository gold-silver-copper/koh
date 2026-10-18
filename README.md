# koh

A Rust, peer-to-peer remote shell inspired by [mosh](https://mosh.org), built on [iroh](https://iroh.computer) / QUIC.

koh gives you a responsive remote shell that survives network changes, suspend/resume, and reconnects — without SSH, port forwarding, or server-side accounts.

## Install and usage

```sh
cargo install --locked koh
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

The same server runs one command, or copies files, with no shell session at all:

```sh
koh exec laptop -- make test          # its stdout and stderr apart, and koh exits with its status
git diff | koh exec laptop -- 'cd src/app && git apply'
koh cp -r ./site laptop:              # a whole tree, into the server user's home (-r and -p, as
                                      # scp takes them, change nothing: trees, modes, times are kept)
koh cp laptop:notes.md laptop:todo .  # back here, into the current directory
```

Or run `koh` alone on a terminal for a menu of this machine's keys, the servers it connects to
and the clients allowed here: pick one by number to connect, rename or delete it; `a` adds one,
`k` shows both keys in full with QR codes and resets one, saying first who will lose access.

Useful commands:

```sh
koh                       # on a terminal: the menu of keys, servers and clients
koh id                    # print this machine's endpoint id (its client key's)
koh servers               # the servers you connect to: add <name> <id> [--direct IP:PORT],
                          # rm <name>, rename <old> <new>
koh clients               # the clients allowed here, likewise
koh serve                 # host a shell for the saved clients (--allow <id> adds one for this run)
koh connect <name|id>     # connect to a saved server, or to a server id: your session there
                          # attached last, else a new one
koh connect <name> --new  # a new session beside your others; --session N picks one by number
koh sessions <name>       # your sessions there, one a line: number, attached or detached, age,
                          # size, running or exited, title
koh exec <name> -- CMD... # run CMD with no terminal ($SHELL -c, in the server user's home) and exit
                          # with its status: stdin goes to it, stdout and stderr come back apart
koh cp SRC... <name>:DST  # copy files and directory trees there, or `koh cp <name>:SRC... DST`
                          # back; ~ and relative paths are the server user's home
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
--shell <program>         # host a program instead of $SHELL (repeat to pass args)
--key-file <path>         # use a custom identity-key path
--direct <ip:port>        # dial a server directly (LAN, loopback), as connect, exec, cp, sessions do;
                          # saved with `koh servers add`, every command dialing that name does
--session-ttl-secs <n>    # keep detached sessions around longer/shorter
--max-connections <n>     # limit concurrent connections
--max-sessions <n>        # limit sessions, all clients' together
```

**Copies land whole.** `koh cp` writes each file or tree it copies beside its target under a
hidden `.koh-….part` name and renames it into place once all of it is written, so a copy cut short
leaves nothing that looks complete; it replaces a file, but never merges a directory into one
already there. A source given on the command line is followed if it is a symlink, as `cp` does;
symlinks inside a tree are copied as symlinks, and fifos, sockets and devices are skipped and
said so. Remote paths are taken as the server user's shell would take them, but not globbed: no
remote shell runs. `koh exec` exits 255 on its own errors (not reached, refused), as ssh does.

Keys live under `$XDG_CONFIG_HOME/koh/` (else `~/.config/koh/`) by default (`client.key`,
`server.key`), and the names beside them: `servers` beside the client key and `clients` beside the
server key, one `name id` a line (`#` comments allowed); a server's may end `direct=IP:PORT` or
`relay=URL`, how to dial it. They are checked as the keys are, since `clients` decides who may open a
shell: a file that is a symlink or someone else's is refused, and a loose mode is tightened.

**Keys, mouse and pastes** reach the remote program as it asked, whatever terminal you type on: the
client decodes what your terminal sends (it turns on the kitty keyboard protocol in a terminal that
speaks it, so Ctrl-I and Tab, or Shift-Enter and Enter, stay apart) and the server encodes each key
for the program, kitty's encoding to nvim or helix, legacy bytes to the rest.

**Platforms:** Linux, macOS, and Android via [Termux](https://termux.dev). Windows is not supported; use WSL2.

## Scripts and agents

`koh connect` needs a terminal; run with none (from a script, or an agent's tool call), it says so
and points at `exec` and `cp`. Everything else works without one.

Save a server with how to reach it, once, and every command dialing its name uses that:

```sh
koh servers add box <server-id> --direct 192.168.1.20:4433   # or --relay-url URL
```

Run a command: its stdout, stderr and exit status come back as a local command's would.

```sh
koh exec box -- cargo test -j 4
koh exec box -- 'cd ~/app && git status --short' > status.txt
```

Copy files and trees either way:

```sh
koh cp -r ./src box:app/              # here to there
koh cp box:app/target/report.json .   # there to here
```

Get a second shell beside the first, and find it again later:

```sh
koh connect box --new                 # a new session; your others keep running
koh sessions box                      # their numbers, attached or not, and titles
koh connect box --session 2           # back to session 2
```

Prompt marks (OSC 133) from the remote shell pass through to your terminal, so one that reads
them, as [fux](https://github.com/gold-silver-copper/fux) does, sees where each remote command
starts and ends, and its status, as it would a local one's.

## Android / Termux install

1. Install Termux from the [Termux GitHub releases](https://github.com/termux/termux-app/releases). Do not use the old Play Store build.
2. In Termux, install Rust and build tools:

   ```sh
   pkg update
   pkg install rust clang pkg-config
   ```

3. Install koh:

   ```sh
   cargo install --locked koh
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
- Detachable sessions survive suspend/resume, IP changes, and reconnects without tmux; a client
  may have several, by number.
- No SSH bootstrap and no port forwarding: the server listens on one UDP port (random unless `--port`), reached through iroh's relays and hole-punching, and admits only allowlisted keys.
- Not wire-compatible with mosh or SSH; koh is its own protocol/tool.
- Intended for personal machines you control; not a full SSH replacement.
- Scrollback: `Ctrl-^ [` opens the server's history above the live screen, in full colour, with
  the arrows, Page Up/Down, the mouse wheel, `/` to search and `q` to leave; new output keeps
  arriving below.
- Shell integration marks (OSC 133) reach your terminal: the rows where the remote shell's prompts
  start, and each command's start and end with its status, so a terminal (or fux's `· done` and
  `last-output`) sees remote commands as local ones. Commands that end between two screen updates
  end as one, with the last one's status; output that scrolled off before an update starts at the
  screen's top. The remote shell must send the marks (koh adds no shell integration).
- Runs one command (`koh exec`) or copies files and trees (`koh cp`) over the same connection and
  allowlist as a shell, with no SSH or remote shell needed.
- Does not provide multi-user accounts, port forwarding, or Windows support.

## Status

koh is experimental and intended for personal use on machines you control.

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the security model, [`SECURITY.md`](SECURITY.md) for vulnerability reporting, and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for implementation details.

## License

MIT, from 0.10.0 onward. Releases before 0.10.0 remain available under GPL-3.0-or-later.
